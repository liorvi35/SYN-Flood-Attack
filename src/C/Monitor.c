/**
 * @brief this file contains implementations for monitor
 * @note all declarations explanations are in our header file `Monitor.h`
 * @since 17/05/2023
 * @authors Lior Vinman & Yoad Tamar
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <errno.h>

#include "Monitor.h" // our header


unsigned short calculate_checksum(void *b, int len)
{	
    unsigned short *buf = b;
	unsigned int sum=0;
	unsigned short result = 0;

	for ( sum = 0; len > 1; len -= 2 )
    {
        sum += *buf++;
    }

	if ( len == 1 )
    {
        sum += *(unsigned char*)buf;
    }

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}

void process_signal(int sig)
{
    fprintf(file, "%f\n", (avg /= seq));

    close(sock);
    if(file)
    {
        fclose(file);
        file = NULL;
    }
    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
    signal(SIGINT, process_signal);

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sock <= 0)
    {
        perror("socket() failed");
        exit(errno);
    }

    socklen_t addr_len = sizeof(struct sockaddr_in);
    struct sockaddr_in target_addr = {0}, recv_addr = {0};
    memset(&target_addr, 0, addr_len);
    memset(&recv_addr, 0, addr_len);

    target_addr.sin_family = AF_INET;
    target_addr.sin_addr.s_addr = inet_addr(TARGET_IP_ADDR);

    file = fopen(RESULTS_FILE, "w");
    if(file == NULL)
    {
        perror("fopen() failed");
        close(sock);
        exit(errno);
    }

    struct timeval start = {0}, end = {0};
    memset(&start, 0, sizeof(struct timeval));
    memset(&end, 0, sizeof(struct timeval));

    char ping_pkt[PACKET_SIZE] = {0}, pong_pkt[PACKET_SIZE] = {0};
    memset(ping_pkt, 0, 64);
    memset(pong_pkt, 0, 64);


    struct icmphdr *icmph = NULL;
    icmph = (struct icmphdr*)ping_pkt;

    ssize_t bytes_sent = 0, bytes_recv = 0;

    while (1)
    {
        icmph->type = ICMP_ECHO;
        icmph->code = 0;
        icmph->checksum = 0;
        icmph->un.echo.id = htons(0);
        icmph->un.echo.sequence = seq++;
        icmph->checksum = calculate_checksum(icmph, sizeof(struct icmphdr*));

        gettimeofday(&start, NULL);
        bytes_sent = sendto(sock, ping_pkt, 64, 0, (struct sockaddr *)&target_addr, addr_len);

        if(bytes_sent < 0)
        {
            perror("sendto() failed");
            close(sock);
            if(file)
            {
                fclose(file);
                file = NULL;
            }
            exit(errno);
        }

        bytes_recv = recvfrom(sock, pong_pkt, 64, 0, (struct sockaddr*)&recv_addr, &addr_len);

        if(bytes_recv < 0)
        {
            perror("recvfrom() failed");
            close(sock);
            if(file)
            {
                fclose(file);
                file = NULL;
            }
            exit(errno);
        }

        gettimeofday(&end, NULL);

        avg += ((end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0);

        fprintf(file, "%d %f\n", (seq), ((end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0));

        sleep(TIMEOUT);
    }
}
