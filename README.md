# Distributed-Denial-of-Service Attack

## Authors
-   <a href="https://github.com/liorvi35">@Lior Vinman<a/>
-   <a href="https://github.com/yoadtamar">@Yoad Tamar<a/>

## Introduction
In this repository, we have implemented a DDoS attack.<br/>DDoS and DoS are cyber-attacks that work by consuming resources on servers, which prevents them from providing services to legitimate users. In this case, we have implemented a DDoS attack on an Apache2 web server by manipulating the TCP 3-way handshake mechanism.<br/>
The TCP 3-way handshake is a process that is used to establish a connection between a client and a server. The process works as follows:<br/>

1. The client sends a 'SYN' packet to the server.
2. The server responds with a 'SYN-ACK' packet.
3. The client responds with an 'ACK' packet.
<br/>
  
The DDoS attack works by sending a large number of SYN packets to the server (and that's why called a "SYN Flood" attack). The server will respond to each SYN packet with a SYN-ACK packet, but the client will never send an ACK packet. This will cause the server to run out of resources and be unable to respond to legitimate requests.<br/>

This attack is a serious threat to web servers and can cause significant downtime. There are a number of steps that can be taken to mitigate the risk of a DDoS attack, such as using a firewall, implementing a load balancer, and using a content delivery network (CDN).<br/>
  
In addition to the attack, we also implemented a monitoring tool that sends ICMP echo requests (pings) to the server while it is under attack, to measure the response times. 

## Requirements
Before using this attack, make sure your system meets the following requirements:

- Debian-based system (we used Ubuntu 22.04 LTS).
- GCC compiler and Make.
- Python version 3 (we used interpreter version 3.11).
- Docker and Docker Compose.
  
## Building and Installing
To install the attack, please follow these steps:

1.  Clone this repository to your local machine using the following command:<br/>`git clone https://github.com/liorvi35/SYN-Flood-Attack.git`.<br/>
  
2. Set up the Docker container environment by executing the following commands:<br/>`sudo docker-compose build`<br/>`sudo docker-compose up -d -f docker-compose.yml`.
  
3. Access the Docker container machines by running the command:<br/>`sudo docker ps`<br/>`sudo docker exec -it <CONTAINER_ID> /bin/bash`.

4. After opening the containers, for each run, execute the following commands:<br/>
`apt-get update`.<br/>
`apt-get install build-essential`.<br/><br/>
On the Target, also run:<br/>
`apt-get install apache2`.

5. For Python: Install the required modules by running the following command:<br/>`pip3 install -r requirements.txt`.

6. To compile the code in C, use the following command:<br/>`make`.
    
7. Don't forget to disable all containers when you're finished using them:<br/>`sudo docker-compose down`.

  
## Usage
Based on the previous section, there are three Docker machines that have already been opened:
  - `Attacke` - 10.9.0.2
  - `Monitor` - 10.9.0.3
  - `Target` - 10.9.0.4
  <br/>
1. On the Target machine, start the server by running the following commands:<br/>
- `service apache2 start`. <br/>
- `service apache2 status`.
  
2. On the Attacker machine, you can use either Attack.py or Attack.c (compiled with ./Attack) to launch an attack on the Target.<br/>
  
2. On the Monitor machine, you can use either Monitor.py or Monitor.c (compiled with ./Monitor) to monitor the responses from the Target


## Repository Mapping
```
├── Results
│   ├── screenshots
│   │   ├── pings_c.png
|   |   ├── pings_p.png
│   │   ├── syn_pkts_c.png
|   |   └── syn_pkts_p.png
│   ├── pings_results_c.txt
│   ├── pings_results_p.txt
│   ├── syns_results_c_1.txt
│   ├── syns_results_c_2.txt
│   ├── syns_results_p_1.txt
│   └── syns_results_p_2.txt
├── src
│   ├── C
│   │   ├── Attack.c
│   │   ├── Attack.h
│   │   ├── Makefile
│   │   ├── Monitor.c
│   │   └── Monitor.h
│   ├── Python
│   │   ├── Attack.py
│   │   ├── Graphs.ipynb
│   │   ├── Monitor.py
│   │   └── requirements.txt
├── Assignment.pdf
├── LICENSE
├── README.md
├── docker-compose.yml
└── readme.pdf
```

  
## Skills
- C socket programming.
- Pytohn socket programming.
- Version control with Git & Github.
- Computers-Communication & Cyber knowledge.
