#ifndef _ATTACK_H_
#define _ATTACK_H_

#include <stdio.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>


#define SERVER_IP_ADDRESS getenv("SERVER_ADDRESS")
#define SERVER_PORT atoi(getenv("SERVER_PORT"))
#define RESULTS_FILE "syns_results_c.txt"
#define NUM_ITERATIONS 100
#define NUM_PACKETS 10000
#define IP_ADDR_LENGTH 16


struct pseudo_header
{
    unsigned int source_address;
    unsigned int destination_address;
    unsigned char placeholder;
    unsigned int protocol;
    unsigned short tcp_length;

    struct tcphdr tcph;
};



void set_packet(char*, struct iphdr*, struct tcphdr*, struct sockaddr_in, struct pseudo_header, int, FILE*);
unsigned short calculate_checksum(unsigned short*, int);
char* get_random_ipv4(int, FILE*);
int get_random_port();



#endif
