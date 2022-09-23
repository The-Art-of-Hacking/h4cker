# Denial of Service

> ⚡︎ **This chapter has [practical labs](https://github.com/Samsar4/Ethical-Hacking-Labs/tree/master/9-Denial-of-Service)**

## DoS
*A Denial of Service (DoS) is a type of attack on a service that disrupts its normal function and prevents other users from accessing it. The most common target for a DoS attack is an online service such as a website, though attacks can also be launched against networks, machines or even a single program.*

DoS attacks can cause the following problems:
- Ineffective services
- Inaccessible services
- Interruption of network traffic
- Connection interference

## DDoS
*A distributed denial of service (DDoS) attack is launched from numerous compromised devices, often distributed globally in what is referred to as a **botnet**.*

![dos](https://www.imperva.com/learn/wp-content/uploads/sites/13/2019/01/hits-per-second.png)

**Goal:**
- Seeks to take down a system or deny access to it by authorized users.

### **Botnet**
*Network of zombie computers a hacker uses to start a distributed attack.*
  - Botnets can be designed to do malicious tasks including sending **spam, stealing data, ransomware, fraudulently clicking on ads or distributed denial-of-service (DDoS) attacks.**
  - Can be controlled over HTTP, HTTPS, IRC, or ICQ
  
![botnet](https://www.f5.com/content/dam/f5-labs-v2/article/articles/edu/20190605_what_is_a_ddos/DDoS_attack.png)

- **Botnet Scanning Methods**:
  - **Random** -  Randomly looks for vulnerable devices
  - **Hitlist** -  Given a list of devices to scan for vulnerabilities
  - **Topological** -  Scan hosts discovered by currently exploited devices
  - **Local subnet** -  Scans local network for vulnerable devices
  - **Permutation** -  Scan list of devices created through pseudorandom permutation algorithm



## <u>Three Types of DoS / DDoS</u>

### **1. Volumetric attacks**
- Consumes the bandwidth of target network or service.
- Send a massive amount of traffic to the target network with the goal of consuming **so much bandwidth** that users are denied access.
- Bandwitdh depletion attack: Flood Attack and Amplification attack.
  
  - **Attacks**:
    - UDP flood attack
    - ICMP flood attack
    - Ping of Death attack
    - Smurf attack (IP)
    - Fraggle (UDP)
    - Malformed IP packet flood attack
    - Spoofed IP packet flood attack

  > - ⚠️ **Volumetric attacks is measured in Bits per second (Bps).**

### **2. Protocol Attacks**
- Consume other types of resources like **connection state tables** present in the network infrastructure components such as **load balancers, firewalls, and application servers**.
  - **Attacks**:
    - SYN flood attack
    - Fragmentation attack
    - ACK flood attack
    - TCP state exhaustion attack
    - TCP connection flood attack
    - RST attack

  > - ⚠️ **Protocol attacks is measured in Packets per second (Pps).**

### **3. Application Layer Attacks**

- Includes low-and-slow attacks, GET/POST floods, attacks that target Apache, Windows or OpenBSD vulnerabilities and more.
- Consume the resources necessary for the application to run.
- Target web servers, web application and specific web-based apps.
- Abuse higher-layer (7) protocols like HTTP/HTTPS and SNMP.
  - **Attacks**:
    - HTTP GET/POST attack
    - Slowloris attack

  > - ⚠️ **Application layer attacks is measured in Requests per second (Rps).**

  > - ⚠️ **Application level attacks are against weak code.**


## <u>Attacks explanation</u>

### **IP Fragmentation attacks**
- IP / ICMP fragmentation attack is a common form of volumetric DoS. In such an attack, datagram fragmentation mechanisms are used to overwhelm the network.

- Bombard the destination with fragmented packets, causing it to use memory to reassemble all those fragments and overwhelm a targeted network.

- **Can manifest in different ways:**
  - **UDP Flooding** - attacker sends large volumes of fragments from numerous sources.
  - **UDP and ICMP** fragmentation attack - only parts of the packets is sent to the target; Since the packets are fake and can't be reassembled, the server's resources are quickly consumed.
  - **TCP fragmentation attack** - also know as a Teardrop attack, targets TCP/IP reassembly mechanisms; Fragmented packets are prevented from being reassembled. The result is that data packets overlap and the targeted server becomes completely overwhelmed.

### **TCP state-exhaustion attack**
- Attempt to consume connection state tables like: **Load balancers, firewalls and application servers.**

### **Slowloris attack**
*Is an application layer attack which operates by utilizing partial HTTP requests. The attack functions by opening connections to a targeted Web server and then keeping those connections open as long as it can.*

-  ![slowloris](https://www.cloudflare.com/img/learning/ddos/ddos-slowloris-attack/slowloris-attack-diagram.png)

- The attacker first opens multiple connections to the targeted server by sending multiple partial HTTP request headers.
- The target opens a thread for each incoming request
- To prevent the target from timing out the connections, the attacker periodically sends partial request headers to the target in order to keep the request alive. In essence saying, “I’m still here! I’m just slow, please wait for me.”
- The targeted server is never able to release any of the open partial connections while waiting for the termination of the request.
- Once all available threads are in use, the server will be unable to respond to additional requests made from regular traffic, resulting in denial-of-service.

### **SYN attack**
- Sends thousands of SYN packets
- Uses a **false source address** / spoofed IP address.
- The server then responds to each one of the connection requests and leaves an open port ready to receive the response.
- Eventually engages all resources and exhausts the machine

### **SYN flood (half-open attack)**
- Sends thousands of SYN packets
- While the **server waits for the final ACK packet**, **<u>which never arrives</u>**, the attacker continues to send more SYN packets. The arrival of each new SYN packet causes the server to temporarily maintain a new open port connection for a certain length of time, and once all the available ports have been utilized the server is unable to function normally.
- Eventually bogs down the computer, runs out of resources.

- ![syn-flood](https://www.cloudflare.com/img/learning/ddos/syn-flood-ddos-attack/syn-flood-attack-ddos-attack-diagram-2.png)

### **ICMP flood**
- Sends ICMP Echo packets with a spoofed address; eventually reaches limit of packets per second sent
  - Is possible to use `hping3` to perform ICMP flood:
    - `hping -1 --flood --rand-source <target>`

### **Smurf attack**
- The Smurf attack is a **distributed denial-of-service** attack in which large numbers of ICMP packets with the intended victim's **spoofed source IP are broadcast to a computer network using an IP broadcast address.**
  - Is possible to use `hping3` to perform this attack and bash script to loop through the subnet.
    - `hping3 -1 -c 1000 10.0.0.$i --fast -a <spoofed target>`
  - ![smurf](https://www.imperva.com/learn/wp-content/uploads/sites/13/2019/01/smurf-attack-ddos.png)

### **Fraggle**
- Same concept as Smurf attack but with **UDP packets** (UDP flood attack).
  - Is possible to use `hping3` to perform Fraggle attack/ UDP flood
    - `hping3 --flood --rand-source --udp -p <target>`

### **Ping of Death**
- Fragments ICMP messages; after reassembled, the ICMP packet is larger than the maximum size and crashes the system
  -  Performs by sending an IP packet larger than the 65,536 bytes  allowed by the IP protocol.
  - Old technique that can be acceptable to old systems. 

### **Teardrop**
- Overlaps a large number of garbled IP fragments with oversized payloads; causes older systems to crash due to fragment reassembly

### **Peer to peer**
- Clients of peer-to-peer file-sharing hub are disconnected and directed to connect to the target system

### **Multi-vector attack**
- Is a combination of **Volumetric, protocol, and application-layer attacks**.

### **Phlashing / Permanent DoS**
- A DoS attack that causes permanent damage to a system.
- Modifies the firmware and can also cause a **system to brick**.
- *e.g: Send fraudulent hardware update to victim; crashing BIOS.*

### **LAND attack**
- Sends a SYN packet to the target with a spoofed IP the same as the target; if vulnerable, target loops endlessly and crashes


## <u>DoS/DDoS Attack Tools:</u>
- **Low Orbit Ion Cannon** (LOIC) - DDoS tool that floods a target with TCP, UDP or HTTP requests
  -  ![loic](https://i.ytimg.com/vi/HavEPVxUn-A/maxresdefault.jpg)

- **High Orbit Ion Cannon** (HOIC) - More powerful version of LOIC; Targets TCP and UDP; The application can open up to 256 simultaneous attack sessions at once, bringing down a target system by sending a continuous stream of junk traffic until legitimate requests are no longer able to be processed; 
  -  ![hoic](https://upload.wikimedia.org/wikipedia/commons/d/d8/HOIC_INTERFACE.png)

- **Other Tools**
  - HULK
  - Metasploit
  - Nmap
  - Tsunami
  - Trinity - Linux based DDoS tool
  - Tribe Flood Network - uses voluntary botnet systems to launch massive flood attacks
  - RUDY (R-U-Dead-Yet?) - DoS with HTTP POST via long-form field submissions

## <u>Mitigations</u>
- Traffic analysis
- Filtering
- Firewalls
- ACLs
- Reverse Proxies
- Rate limiting - limiting the maximum number of connections a single IP address is allowed to make)
- Load balancers
- DoS prevention software
