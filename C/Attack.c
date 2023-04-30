#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "Attack.h"

/*
1. create a RAW socket
2. build my packet (build tcp, ip headers)
3. send the packet
*/



int main()
{

    char buffer[4096];
    struct iphdr *ip = (struct iphdr *) buffer;
    struct tcphdr *tcp = (struct tcphdr *) (buffer + sizeof(struct iphdr));
    struct sockaddr_in sin;

    int sock = 0;
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("socket() failed");
        exit(-1);
    }

    int one = 1;
    const int *val = &one;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("setsockopt() failed");
        exit(errno);
    }
    
    /* Fill in IP header */
    ip.ihl = 5;
    ip.version = 4;
    ip.tos = 0;
    ip.tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ip.id = htons(54321);
    ip.frag_off = 0;
    ip.ttl = 255;
    ip.protocol = IPPROTO_TCP;
    ip.check = 0;
    ip.saddr = inet_addr("10.0.2.15");
    ip.daddr = inet_addr("8.8.8.8");

    /* Fill in TCP header */
    tcp.source = htons(1234);
    tcp.dest = htons(80);
    tcp.seq = htonl(1);
    tcp.ack_seq = 0;
    tcp.doff = 5;
    tcp.syn = 1;
    tcp.psh = 0;
    tcp.window = htons(5840);
    tcp.check = 0;
    tcp.urg_ptr = 0;
    tcp->res1 = 0;
    tcp->urg = 0;
    tcp->ack = 0;
    tcp->rst = 0;
    tcp->fin = 0;

    tcp->check = htons(~(htons(ip->tot_len) + IPPROTO_TCP + *(unsigned short *)&tcp));    

    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    

    if (sendto(sock, buffer, ip->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto()");
        exit(-1);
    }

    return 0;


}
