#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#define PACKET_SIZE 64

int main() {
    struct sockaddr_in addr_ping, addr_recv;
    struct timeval start, end;
    struct icmphdr *icmp_hdr;
    char send_packet[PACKET_SIZE];
    socklen_t addr_len;
    int icmp_seq = 0;
    int sockfd, send_count = 0;
    long int total_time = 0, avg_time;
    FILE *fp;

    memset(&addr_ping, 0, sizeof(addr_ping));
    memset(&addr_recv, 0, sizeof(addr_recv));
    memset(send_packet, 0, sizeof(send_packet));
    memset(recv_packet, 0, sizeof(recv_packet));

    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    addr_ping.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &addr_ping.sin_addr);

    fp = fopen("ping_log_c", "w");
    if (fp == NULL) {
        perror("fopen");
        exit(1);
    }

    while (1) {
        icmp_hdr = (struct icmphdr*)send_packet;
        icmp_hdr->type = ICMP_ECHO;
        icmp_hdr->code = 0;
        icmp_hdr->checksum = 0;
        icmp_hdr->un.echo.id = getpid();
        icmp_hdr->un.echo.sequence = icmp_seq++;
        icmp_hdr->checksum = htons(~(ICMP_ECHO << 8));

        gettimeofday(&start, NULL);

        while(sendto(sockfd, send_packet, PACKET_SIZE, 0, (struct sockaddr*)&addr_ping, sizeof(addr_ping)) < 0) 
        {
            continue;
        }

        gettimeofday(&end, NULL);

        send_count++;

        total_time += (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);

        fprintf(fp, "%d %ld\n", icmp_seq-1, (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec));

        avg_time = total_time / send_count;

        sleep(1);

        if(send_packet % 1000 == 0)
        {
          prinf("send 1000 ping...");
        }
    }

    close(sockfd);
    fclose(fp);

    return 0;
}
