#include <ws2tcpip.h>
#include <iostream>

#include "address_utilities.hpp"

using namespace std;

string get_address(SOCKADDR *socket_address, int socket_address_length)
{
    string host_str;
    char host[NI_MAXHOST], service[NI_MAXSERV];
    int host_length = NI_MAXHOST, service_length = NI_MAXSERV, return_value;

    return_value = getnameinfo(socket_address, socket_address_length, host, host_length, service, service_length, NI_NUMERICHOST | NI_NUMERICSERV);
    if (return_value)
    {
        cout << "Niepowodzenie operacji getnameinfo(): " << return_value << endl;
        return "";
    }
    host_str = string(host);

    if (strcmp(service, "0") != 0)
    {
        string service_str(service);
        host_str += ":" + service_str;
    }
    return host_str;
}

string get_host_name(SOCKADDR *socket_address, int socket_address_length)
{
    string host_str;
    char host[NI_MAXHOST];
    int host_length = NI_MAXHOST, return_value;

    return_value = getnameinfo(socket_address, socket_address_length, host, host_length, NULL, 0, 0);
    if (return_value)
    {
        cout << stderr << "Niepowodzenie operacji getnameinfo(): " << return_value << endl;
        return "";
    }
    host_str = string(host);
    return host_str;
}

bool compare_addresses(SOCKADDR *socket_address1, SOCKADDR *socket_address2)
{
    int return_value = 1;
    if (socket_address1->sa_family == socket_address2->sa_family)
        return_value = memcmp(&((SOCKADDR_IN *)socket_address1)->sin_addr, &((SOCKADDR_IN *)socket_address2)->sin_addr, sizeof(in_addr));
    return return_value == 0;
}

addrinfo *resolve_address(string address, string port)
{
    addrinfo hints, *resolve = NULL;
    int return_value;

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = address.empty() ? 0 : AI_PASSIVE;
    hints.ai_family = AF_INET;

    return_value = getaddrinfo(address.c_str(), port.c_str(), &hints, &resolve);
    if (return_value)
    {
        cout << "Nieprawidlowy adres: " << address << " Kod bledu: " << return_value << endl;
        return NULL;
    }
    return resolve;
}
