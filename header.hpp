#ifndef IP_HEADER_HPP
#define IP_HEADER_HPP

#include <ws2ipdef.h>

#define ICMP_ECHO_REQUEST_TYPE 8
#define ICMP_ECHO_REQUEST_CODE 0
#define ICMP_ECHO_REPLY_TYPE 0
#define ICMP_ECHO_REPLY_CODE 0

struct ip_header
{
    unsigned char ver_length;
    unsigned char type_of_service;
    unsigned short total_length;
    unsigned short id;
    unsigned short offset;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned int source_address;
    unsigned int destination_address;
};

struct icmp_header
{
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
    unsigned short id;
    unsigned short sequence;
    unsigned long timestamp;
};

#endif