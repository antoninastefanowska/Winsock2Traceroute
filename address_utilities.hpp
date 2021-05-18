#ifndef RESOLVE_HPP
#define RESOLVE_HPP

#include <winsock2.h>
#include <string>

using namespace std;

string get_address(SOCKADDR *socket_address, int socket_address_length);
string get_host_name(SOCKADDR *socket_address, int socket_address_length);
bool compare_addresses(SOCKADDR *socket_address1, SOCKADDR *socket_address2);
addrinfo *resolve_address(string address, string port);

#endif