#ifndef _ATTACK_H_
#define _ATTACK_H_

#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define RESULTS_FILE "syns_results_c.txt"
#define TARGET_IP_ADDR "10.9.0.3"
#define TARGET_PORT 80
#define NUM_PACKETS 10000
#define NUM_ITERATIONS 100

void set_ip_layer(struct sockaddr_in*, struct iphdr*, int, FILE*);
void set_tcp_layer(struct sockaddr_in*, struct iphdr*, struct tcphdr*);

uint16_t calculate_ip_checksum(struct iphdr*);
uint16_t calculate_tcp_checksum(struct iphdr*, struct tcphdr*);


int get_random_port();
char* get_random_ipv4(int, FILE*);

#endif
