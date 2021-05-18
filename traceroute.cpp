#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <chrono>

using namespace std::chrono;

#include "header.hpp"
#include "address_utilities.hpp"

#define DATA_SIZE 32
#define TIMEOUT 5000
#define MAX_TTL 100

using namespace std;

unsigned short checksum(unsigned short *buffer, int size)
{
    unsigned long sum = 0;
    int i = 0;

    while (size > 1)
    {
        sum += buffer[i++];
        size -= sizeof(unsigned short);
    }
    if (size)
        sum += *(unsigned char *)buffer;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void init_icmp_header(char *buffer, int datasize)
{
    icmp_header *header = (icmp_header *)buffer;
    char *datapart;

    header->type = ICMP_ECHO_REQUEST_TYPE;
    header->code = ICMP_ECHO_REQUEST_CODE;
    header->id = (unsigned short)GetCurrentProcessId();
    header->checksum = 0;
    header->sequence = 0;
    header->timestamp = GetTickCount();

    datapart = buffer + sizeof(icmp_header);
    memset(datapart, 'A', datasize);
}

void set_icmp_sequence(char *buffer)
{
    icmp_header *header = (icmp_header *)buffer;
    unsigned long sequence = GetTickCount();
    header->sequence = (unsigned short)sequence;
}

void set_icmp_checksum(char *buffer, int packet_length)
{
    icmp_header *header = (icmp_header *)buffer;
    header->checksum = 0;
    header->checksum = checksum((unsigned short *)buffer, packet_length);
}

int post_receive_from(SOCKET socket, char *buffer, int buffer_length, SOCKADDR *from, int *from_length, WSAOVERLAPPED *overlapped)
{
    WSABUF wsa_buffer;
    DWORD flags = 0, bytes;
    int return_value = NO_ERROR;

    wsa_buffer.buf = buffer;
    wsa_buffer.len = buffer_length;

    return_value = WSARecvFrom(socket, &wsa_buffer, 1, &bytes, &flags, from, from_length, overlapped, NULL);
    if (return_value == SOCKET_ERROR)
        if (WSAGetLastError() != WSA_IO_PENDING)
            cout << "Niepowodzenie operacji WSARecvFrom(): " << WSAGetLastError() << endl;

    return return_value;
}

int analyze_packet(char *buffer)
{
    int ip_header_length, return_value = NO_ERROR;
    ip_header *header_ip = (ip_header *)buffer;
    icmp_header *header;

    ip_header_length = (header_ip->ver_length & 0x0F) * 4;
    if (header_ip->protocol == IPPROTO_ICMP)
    {
        header = (icmp_header *)&buffer[ip_header_length];
        if (header->type != ICMP_ECHO_REPLY_TYPE && header->code != ICMP_ECHO_REPLY_CODE)
        {
            cout << "Bledny komunikat." << endl;
            return_value = SOCKET_ERROR;
        }
    }
    else
    {
        cout << "Bledny komunikat." << endl;
        return_value = SOCKET_ERROR;
    }
    return return_value;
}

int set_ttl(SOCKET socket, int ttl)
{
    int option_level = IPPROTO_IP, option = IP_TTL, return_value = NO_ERROR;
    return_value = setsockopt(socket, option_level, option, (char *)&ttl, sizeof(ttl));
    return return_value;
}

int main(int argc, char *argv[])
{
    WSADATA wsd;
    SOCKET my_socket = INVALID_SOCKET;
    SOCKADDR_STORAGE from;
    DWORD bytes, flags;
    WSAOVERLAPPED receive_overlapped;

    addrinfo *destination, *local;

    char *icmp_buffer, receive_buffer[0xFFFF];
    int packet_length = 0, receive_buffer_length = 0xFFFF, from_length, ttl, return_value;
    bool done = false, resolve = false;
    float time, total_time = 0;
    string destination_address(argv[1]), ip_address, host_name;
    high_resolution_clock::time_point start, finish;

    /* przykład: traceroute.exe www.google.com -r */
    if (argc >= 3 && strcmp(argv[2], "-r") == 0)
        resolve = true;

    if (WSAStartup(MAKEWORD(2, 2), &wsd))
    {
        cout << "Niepowodzenie operacji WSAStartup(): " << WSAGetLastError() << endl;
        return -1;
    }

    destination = resolve_address(destination_address, "0");
    if (destination == NULL)
    {
        cout << "Nieprawidlowy adres." << endl;
        return -1;
    }

    ip_address =  get_address(destination->ai_addr, destination->ai_addrlen);
    cout << "Adres docelowy: " << destination_address << " | IP: " << ip_address << endl;

    local = resolve_address("", "0");
    if (local == NULL)
    {
        cout << "Nie mozna uzyskac adresu lokalnego." << endl;
        return -1;
    }

    ip_address = get_address(local->ai_addr, local->ai_addrlen);
    cout << "Lokalny adres IP: " << ip_address << endl << endl;

    my_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (my_socket == INVALID_SOCKET)
    {
        cout << "Wystapil blad przy tworzeniu socketa: " << WSAGetLastError() << endl;
        return -1;
    }

    packet_length += sizeof(icmp_header);
    packet_length += DATA_SIZE;

    icmp_buffer = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, packet_length);
    if (icmp_buffer == NULL)
    {
        cout << "Wystapil blad alokacji: " << GetLastError() << endl;
        return -1;
    }
    init_icmp_header(icmp_buffer, DATA_SIZE);

    if (bind(my_socket, local->ai_addr, local->ai_addrlen) == SOCKET_ERROR)
    {
        cout << "Wystapil blad bindowania socketa: " << WSAGetLastError() << endl;
        return -1;
    }
    
    memset(&receive_overlapped, 0, sizeof(receive_overlapped));
    receive_overlapped.hEvent = WSACreateEvent();

    from_length = sizeof(from);
    post_receive_from(my_socket, receive_buffer, receive_buffer_length, (SOCKADDR *)&from, &from_length, &receive_overlapped);
    ttl = 1;
    while (!done && ttl < MAX_TTL)
    {
        done = false;
        set_ttl(my_socket, ttl);
        set_icmp_sequence(icmp_buffer);
        set_icmp_checksum(icmp_buffer, packet_length);

        start = high_resolution_clock::now();
        if (sendto(my_socket, icmp_buffer, packet_length, 0, destination->ai_addr, destination->ai_addrlen) == SOCKET_ERROR)
        {
            cout << "Wystapil blad przy wysylaniu komunikatu: " << WSAGetLastError();
            return -1;
        }

        return_value = WaitForSingleObject((HANDLE)receive_overlapped.hEvent, TIMEOUT);
        if (return_value == WAIT_FAILED)
        {
            cout << "Wystapil blad przy oczekiwaniu na odpowiedz: " << GetLastError() << endl;
            return -1;
        }
        else if (return_value == WAIT_TIMEOUT)
            cout << "Przekroczono limit czasu oczekiwania." << endl;
        else
        {
            if (WSAGetOverlappedResult(my_socket, &receive_overlapped, &bytes, FALSE, &flags) == FALSE)
                cout << "Niepowodzenie operacji WSAGetOverlappedResult(): " << WSAGetLastError() << endl;

            finish = high_resolution_clock::now();
            time = duration_cast<nanoseconds>(finish - start).count() / 1000000.0;
            total_time += time;
            WSAResetEvent(receive_overlapped.hEvent);
            if (analyze_packet(receive_buffer) == NO_ERROR)
            {
                ip_address = get_address((SOCKADDR *)&from, from_length);
                cout << "TTL: " << ttl << " | Czas: " << time << "ms | IP: " << ip_address;
                if (resolve)
                {
                    host_name = get_host_name((SOCKADDR *)&from, from_length);
                    if (host_name.empty())
                        cout << endl << "Wystapil blad przy probie odnalezienia nazwy hosta." << endl;
                    else
                        cout << " | Nazwa: " << host_name;
                }
                cout << endl;
                done = compare_addresses(destination->ai_addr, (SOCKADDR *)&from);
                ttl++;
            }
            if (!done)
            {
                from_length = sizeof(from);
                post_receive_from(my_socket, receive_buffer, receive_buffer_length, (SOCKADDR *)&from, &from_length, &receive_overlapped);
            }
        }
        Sleep(1000);
    }
    cout << endl << "Osiagnieto adres docelowy. Calkowity czas: " << total_time << "ms" << endl;

    freeaddrinfo(destination);
    freeaddrinfo(local);
    if (my_socket != INVALID_SOCKET)
        closesocket(my_socket);
    HeapFree(GetProcessHeap(), 0, icmp_buffer);
    WSACleanup();

    return 0;
}