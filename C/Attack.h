#ifndef ATTACK_H
#define ATTACK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <errno.h>

#define S_IP "10.9.0.2"
#define S_PORT 12345
#define D_IP "10.9.0.3"
#define D_PORT 80
#define NUM_ITERATIONS 100
#define NUM_PACKETS 10000
#define SYN_TIMES_FILE "syns_results_c.txt"

void set_ip_layer(struct iphdr*);
void set_tcp_layer(struct tcphdr*);

#endif