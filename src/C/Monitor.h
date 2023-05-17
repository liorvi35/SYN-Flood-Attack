/**
 * @brief this file contains declarations for monitor
 * @since 17/05/2023
 * @authors Lior Vinman & Yoad Tamar
 */


#ifndef MONITOR_H

    #include <stdio.h>

    /**
    * @brief a flag to mark the header file (so wont be included more than once in total)
    */
    #define MONITOR_H

    /**
     * @brief target's ipv4 address
     * @note this is the `Target` docker in the `docker-compose.yml`
     */
    #define TARGET_IP_ADDR "10.9.0.4"

    /**
     * @brief size of ping & pong packets
     */
    #define PACKET_SIZE 64

    /**
     * @brief sleep time after each ping-pong
     */
    #define TIMEOUT 5

    /**
     * @brief filename of the results
     */
    #define RESULTS_FILE "pings_results_c.txt"

    /**
     * @brief file pointer for results
     * @note should be global for ^C usage
     */
    FILE *file = NULL;

    /**
    * @brief file pointer for results
    * @note should be global for ^C usage
    */
    double avg = 0.0;

    /**
    * @brief socket file descriptor
    * @note should be global for ^C usage
    */
    int sock = 0;

    /**
    * @brief packets sequence number
    * @note should be global for ^C usage
    */
    int seq = 0;

    /**
     * @brief this function calculates the checksum for IP and TCP headers
     * @param void* header pointer
     * @param int number of bytes to be checksummed
     * @return header checksum
     */
    unsigned short calculate_checksum(void*, int);

    /**
     * @brief this function handles the ^C signal
     * @param sig signal id
     */
    void process_signal(int sig);

#endif
