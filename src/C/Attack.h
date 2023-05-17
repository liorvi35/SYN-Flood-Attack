/**
 * @brief this file contains declarations for DDoS attack
 * @since 17/05/2023
 * @authors Lior Vinman & Yoad Tamar
 */

#ifndef ATTACK_H

    #include <netinet/tcp.h>
    #include <stdio.h>

    /**
     * @brief a flag to mark the header file (so wont be included more than once in total)
    */
    #define ATTACK_H

    /**
     * @brief maximal length of characters in ipv4 address
     */
    #define IP_ADDR_LEN 16

    /**
     * @brief filename of the results
     */
    #define RESULTS_FILE "syns_results_c.txt"

    /**
     * @brief target's ipv4 address
     * @note this is the `Target` docker in the `docker-compose.yml`
     */
    #define TARGET_IP_ADDR "10.9.0.4"

    /**
     * @brief target's port number
     * @note 80 for attacking HTTP
     */
    #define TARGET_PORT 80

    /**
     * @brief number of iterations of the attack
     */
    #define NUM_ITERATIONS 100

    /**
     * @brief number of packets we are sending in each iteration
     */
    #define NUM_PACKETS 10000

    /**
     * @brief the size of the `SYN` packet we are sending
     */
    #define SYN_PACKET_SIZE 4096


    /**
     * @brief pseudo header that will be used in tcp header checksum calculation
     */
    struct pseudo_header
    {
        /* sender address */
        unsigned int source_address;

        /* receiver address */
        unsigned int dest_address;

        /* padding */
        unsigned char placeholder;

        /* used protocol */
        unsigned char protocol;

        /* length of header & data */
        unsigned short tcp_length;

        /* header itsealf */
        struct tcphdr tcp;
    };

    /**
     * @brief this function calculates the checksum for IP and TCP headers
     * @param usort* header pointer
     * @param int number of bytes to be checksummed
     * @return header checksum
     */
    unsigned short calculate_checksum(unsigned short*, int);

    /**
     * @brief this function randomize an ipv4 address
     * @param sock socket file descriptor
     * @return a string that represents a random ipv4 address
     * @note sock & file needed only for closing in case of error
     */
    char *get_random_ipv4(int sock, FILE*);

    /**
     * @brief this function randomize a port number
     * @return random port number
     */
    int get_random_port();

#endif
