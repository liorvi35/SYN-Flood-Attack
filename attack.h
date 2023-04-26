#ifndef ATTACK_H
#define ATTACK_H

#define S_IP "10.9.0.2"
#define S_PORT 12345
#define D_IP "10.9.0.3"
#define D_PORT 80
#define NUM_ITERATIONS 100
#define NUM_PACKETS 10000

void set_ip_layer(struct iphdr);
void set_tcp_layer(struct tcphdr);


#endif