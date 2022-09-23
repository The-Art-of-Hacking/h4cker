# Evading IDS, Firewalls and Honeypots

## <u>IDS/IPS - Basic Concepts</u>

**Intrusion Prevention System (IPS)** - ACTIVE monitoring of activity looking for anomalies and alerting/notifiying AND **taking action when they are found**.

**Intrusion Detection System (IDS)** - PASSIVE monitoring of activity looking for anomalies and alerting/notifying when they are found.

<p align="center">
<img width="75%" src="https://3th2q02cq5up44zpe81rwase-wpengine.netdna-ssl.com/wp-content/uploads/2019/11/Intrusion-Detection-IDS-VS-Intrusion-Prevention-IPS-What%E2%80%99s-The-Difference.png" />
</p>

### **Deployment Types - HIDS & NIDS & WIDS:**
1. **Host based** - Monitors activity on a single device/host by being installed lcoally.

2. **Network based** - Monitors activity across a network using remote sensors that reprot back to a central system. Often paired with a security Information & SIEM system for analysis. Often Reverse ARP or Reverse DNS lookups are used to discover the source

### **Knowledge & Behavior-Based Detection:**
1. **Knowledge Based (Signature Based | Pattern Matching)** - Most common form of detection. Uses a database of profiles, or signatures to assess all traffic against.

2. **Behavior Based (Statistical | Anomaly | Heuristic)** - Starts by creating a baseline of behavior for the monitored system/network and then comapres all traffic against that looking for deviations. Can be labeled an AI or Expert system.

---
### **Types of IDS Alerts**
- **True Positive** --> Attack - Alert ✅✅
- **False Positive** --> No Attack - Alert ❌✅
- **False Negative** --> Attack - No Alert ✅❌
  - *This is the worst scenario*
- **True Negative** --> No Attack - No Alert ❌❌

---

## <u>Firewalls - Basic Concepts</u>
*Firewalls are often seen as NAC devices. Use of rule sets to filter traffic can implement security policy.*

### **Firewalls types:**
- **Stateful (Dynamic Packet Filtering)** - Layer 3 + 4 (Network + Transport layer)
- **Stateless (Static Packet Filtering)** - Layer 3 (Network)
- **Deep Packet Inspection** - Layer 7 (Application Layer)
- **Proxy Firewall** - Mediates communications between unstrusted and trusted end-points (server/hosts/clients). A proxy firewall is a network security system that protects network resources by filtering messages at the Application Layer 7. A proxy firewall may also be called an application firewall or gateway firewall.

### **Proxy Types:**
- **Circuit-level proxy** - Firewall that works on **Layer 5 (Session layer)**; They monitor TCP handshaking between packets to determine whether a requested session is legitimate.
- **Application-level proxy** - Any service or server that acts as a proxy for client computer requests at the application’s protocols.

> **⚠️ An <u>application-level proxy</u> is one that knows about the particular application it is providing proxy services for; it understands and interprets the commands in the application protocol. A <u>circuit-level proxy</u> is one that creates a circuit between the client and the server without interpreting the application protocol.**

- **Multi-homed Firewall (dual-homed)** - Firewall that has two or more interfaces; One interface is connected to the untrusted network and another interface is connected to the trusted network. A DMZ can be added to a multi-homed firewall just by adding a third interface.

- **Bastion hosts** - Endpoint that is exposed to the internet but has been hardened to withstand attacks; Hosts on the screened subnet designed to protect internal resources.

- **Screened host** - Endpoint that is protected by a firewall.

- **Packet-filtering** - Firewalls that only looked at headers


> ⚠️ Only uses rules that **implicitly denies** traffic unless it is allowed.

> ⚠️ Oftentimes uses **network address translation** (NAT) which can apply a one-to-one or one-to-many relationship between external and internal IP addresses.

> ⚠️ **Private zone** - hosts internal hosts that only respond to requests from within that zone


## <u>Honeypots</u> 🍯
*Honeypots are decoy systems or servers deployed alongside production systems within your network. When deployed as enticing targets for attackers, honeypots can add security monitoring opportunities for blue teams and misdirect the adversary from their true target.*

- **Honeynet** - Two or more honeypots on a network form a honeynet. Honeynets and honeypots are usually implemented as parts of larger Network Intrusion Detection Systems.

- A **Honeyfarm** is a centralized collection of honeypots and analysis tools.

### **Types of Honeypots:**
1. **Low-interaction** ---> Simulates/imitate services and systems that frequently attract criminal attention. They offer a method for collecting data from blind attacks such as botnets and worms malware. 
2. **High interaction** ---> Simulates all services and applications and is designed to be completely compromised
3. **Production** ---> Serve as decoy systems inside fully operating networks and servers, often as part of an intrusion detection system (IDS). They deflect criminal attention from the real system while analyzing malicious activity to help mitigate vulnerabilities.
4. **Research** ---> Used for educational purposes and security enhancement. They contain trackable data that you can trace when stolen to analyze the attack.

- **Honeypot Tools:**
  - Specter
  - Honeyd
  - KFSensor (Honeypot IDS)

## <u>Evading with Nmap</u>

### **Useful switches for Evading and Stealthy**:

Nmap Switch | Information
--|--
`-v` | Verbose level
`-sS` | TCP SYN scan
`-T` | Time template for performing the scan
`-f` | Use fragmented IP packets
`-f --mtu` | Use fragmented packets & set MTU
`-D`|  IP address Decoy: <decoy1,decoy2[,ME],...>: Cloak a scan with decoys
`-S` | Spoof the source IP address
`--send-eth` | Ensures that we use Ethernet level packets. bypassing the IP layer and sends raw Ethernet frames within the flow
`--data-length` | Specify the length of data/frame
`--source-port` | Specify a randomized port that you want to comunicate

---
### **Example:**

• Sends IPv4 fragmented 50-byte packet size; The packets are too small to send data and to detect as a Probe/Scanning technique:

`nmap -v -sS -f -mtu 32 --send-eth --data-length 50 --source-port 8965 -T5 192.168.0.22`

> ⚠️ **Fragmentation is the heart of the IDS/Firewall Evasion techniques.**
---

## <u>Using SNORT</u>
*SNORT is an open source network intrusion detection system (NIDS). Snort is a packet sniffer that monitors network traffic in real time, scrutinizing each packet closely to detect a dangerous payload or suspicious anomalies.*

- Snort is a widely deployed IDS that is open source
- Includes a **sniffer**, **traffic logger** and a **protocol analyzer**
- Runs in three different modes
  - **Sniffer** - Watches packets in real time
  - **Packet logger** - Saves packets to disk for review at a later time
  - **NIDS** - Analyzes network traffic against various rule sets
- Configuration is in `/etc/snort` on Linux and `C:\snort\etc` in Windows; the file is **snort.conf**.

### **SNORT basics commands:**

**Operational modes:**
- Snort as **Sniffer** ---> `snort -v`

- Snort as **Packet logger**  ---> `snort -l`

- Snort as **NIDS** ---> `snort -A` or `snort -c <path_to_conf_file>`

**Example of usage**:

- **`snort -i 4 -l c:\Snort\log -c c:\Snort\etc\snort.conf -T`**
  - *This command will test snort configuration and rules and check if there is any erros without starting up.*
  - `-i 4` ---> interface specifier, in case is interface 4.
  - `-l` ---> for logging
  - `-c` ---> use Snort rules file specifying path
  - `-T` ---> Only For testing, this prevent Snort from start up; Essentially to check if there is any errors and if the rules are good.  

- **`snort -i 4 -c c:\Snort\etc\snort.conf -l c:\Snort\log -K ascii`**
  - *This command will fire up Snort NIDS and log everything in ASCII.*

**Basic commands**:
Flag | Information
-|-
`-A` | Set alert mode: fast, full, console, test or none
`-b` | Log packets in tcpdump format (much faster!)
`-B <mask>` | Obfuscate IP addresses in alerts and packet dumps using CIDR mask
`-c <rules>` | Use Rules file
`-C` | Print out payloads with character data only (no hex)
`-l` | Specifies the logging directory (all alerts and packet logs are placed in this directory)
`-i <interface number>` | Specifies which interface Snort should listen on
`-K` | Logging mode (pcap[default], ascii, none)
`-?` | Lists all switches and options and then exits

### **SNORT Rules**
*SNORT has a rules engine that allows for customization of monitoring and detection capabilities.*

- **There are three available rule actions**
  1. Alert
  2. Pass
  3. Log
- **And three available IP protocols:**
  1. TCP
  2. UDP
  3. ICMP

### **Breaking down a Snort rule:**

> **`alert icmp any any -> &HOME_NET any (msg:"ICMP test"; sid:1000001; rev:1; classtype:icmp-event;)`**

Rule part | Information
-|-
`alert icmp any any -> $HOME_NET any` | **Rule Header** ⬇️
`alert` | Rule action. Snort will generate an alerta when the set condition is met.
`any` (1st) | Source IP. Snort will look at all sources
`any` (2nd) | Source port. Snort will look at all ports
`->` | Direction. From source to destination; *(source -> destination)*
`&HOME_NET` | Destination IP. We are using the HOME_NET value from the snort.conf file which means a variable that defines the network or networks you are trying to protect.
`any` (3rd) | Destination port. Snort will look at all ports on the protected network
`(msg:"ICMP test"; sid:1000001; rev:1; classtype:icmp-event;)` | **Rule Options** ⬇️
`msg:"ICMP test"` | Snort will include this message with the alert
`sid:1000001` | Snort rule ID. Remember all numbers < 1,000,000 are reserved, this is why we are starting with 1000001 (you may use any number, as long as it's grater that 1,000,000)
`rev:1` | Revision number. This option allows for easier rule maintenance
`classtype:icmp-event` | Categorizes the rule as an "icmp-event", one of the predefined Snort categories. This options helps with the rule organization
---
### Rules Examples:
> **`alert tcp 192.168.x.x any -> &HOME_NET 21 (msg:"FTP connection attempt"; sid:1000002; rev:1;)`**
  - TCP alert in a source IP address 192.168.x.x with any port; HOME_NET destination on port 21.

> **`alert tcp $HOME_NET 21 -> any any (msg:"FTP failed login"; content:"Login or password incorrent"; sid:1000003; rev:1;)`**
  - TCP alert in HOME_NET port 21 (FTP) as a source, to any destination IP address and port.

> **`alert tcp !HOME_NET any -> $HOME_NET 31337 (msg : "BACKDOOR ATTEMPT-BackOrifice")`**
  - This alerts about traffic coming not from an external network to the internal one on port 31337.

**Example output**
  - 10/19-14:48:38.543734 0:48:542:2A:67 -> 0:10:B5:3C:34:C4 type:0x800 len:0x5EA    
  - **xxx -> xxx TCP TTL:64 TOS:0x0 ID:18112 IpLen:20 DgmLen:1500 DF**
  - Important info is bolded

## <u>Evasion Concepts and Techniques</u>

- **Insertion Attack** - Attacker forces the IDS to process invalid packets.

- **Evasion** - An endpoint accepts a packet that the IDS would normally reject. Typically executed via **fragmentation** of the attack packets to allow them to be moved through the IDS.

- **Obfuscation** - Encoding the attack packets in such a way that the target is able to decode them, but the IDS is not.
  - Unicode
  - Polymorphic code
  - Encryption
  - Path manipulation to cause signature mismatch

- **False Positive Generation Events** - Crafting malicious packets designed to set off alarms with hope of distracting/overwhelming IDS and operators.

- **Session Splicing** - Just another type of fragmentation attack.

- **Unicode encoding** - works with web requests - using Unicode characters instead of ascii can sometimes get past

- **Fragmentation attack** -  Splits up packets so that the IDS can't detect the real intent

- **Overlapping Fragments** - Generate a bunch of tiny fragments overlapping TCP sequence numbers.

- **Time-To-Live (TTL) Attack** - Requires the attacker to have inside knowledge of the target network to allow for the adjusment of the TTL values to control who gets what packets when.

- **Invalid RST Packets** - Manipulation of the RST flag to trick IDS into ignoring the communication session with the target.

- **Urgency Flag - URG** - Manipulation URG flag to cause the target and IDS to have different sets of packets, because the IDS processes ALL packets irrespective of the URG flag, whereas the target will only process URG traffic.

- **Polymorphic Shellcode** - Blow up the pattern matching by constantly changing.

- **ASCII Shellcode** - Use ASCII characters to bypass pattern matching.

- **Application-Level Attacks** - Taking advantage of the compression used to transfer large files and hide attacks in compressed data, as it cannot be examined by the IDS.

- **Desynchronization** - Manipulation the TCP SYN to fool IDS into not paying attention to the sequence numbers of the illegitimate attack traffic, but rather, give it a false set of sequences to follow.

- **Encryption** - Using encryption to hide attack.

- **Flood the network** - Trigger alerts that aren't your intended attack so that you confuse firewalls/IDS and network admins; Overwhelming the IDS.

> ⚠️ **Slow down** - Faster scanning such as using nmap's -T5 switch will get you caught.  Pros use -T1 switch to get better results

**Tools for Evasion**
  - **Nessus** - Also a vulnerability scanner
  - **ADMmutate** - Creates scripts not recognizable by signature files
  - **NIDSbench** - Older tool for fragmenting bits
  - **Inundator** - Flooding tool

## <u>Firewall Evasion</u>
- **Firewalking** - Using TTL values to determine gateway ACL filters and allow for mapping of internal networks by analyzing IP packet responses; Going through every port on a firewall to determine what is open.

- **Banner Grabbing** - Looking for FTP, TELNET and web server banners.

- **IP Address Spoofing** - Hijacking technique allowing attacker to masquerade as a trusted host.

- **Source Routing** - Allows the sender of a packet to partially or fully specify the route to be used.

- **Tiny Fragments** - Sucessful with Firewalls when they ONLY CHECK for the TCP header info, allowing the fragmentation of the information across multiple packets to hide the true intention of the attack.

- **ICMP Tunneling** - Allows for the tunneling of a backdoor shell via the ICMP echo packets because the RFC (792) does not clearly define what kind of data goes in the data portion of the frame, allowing for attack traffic to be seen as acceptable when inserted. If firewalls do not examine the payload section of the dataframe, they would let the data through, allowing the attack.

- **ACK Tunneling** - Use of the ACK flag to trick firewall into allowing packets, as many firewalls do not check ACK packets.

- **HTTP Tunneling** - Use of HTTP traffic to 'hide' attacks.

- **SSH Tunneling** - Use of SSH to encrypt and send attack traffic.

- **MitM Attacks** - Use of DNS and routing manipulation to bypass firewalls.

- **XSS Attacks** - Allows for the exploitation of vulnerabilities around the processing of input parameters from the end user and the server responses in a web application. The attacker injects malicious HTML/JS code into website to force the bypassing of the firewall once executed.

- *Use IP in place of a URL - may work depending on nature of filtering in place*
- *Use Proxy Servers/Anonymizers - May work depending on nature of filtering in place*
- *ICMP Type 3 Code 13 will show that traffic is being blocked by firewall*
- *ICMP Type 3 Code 3 tells you the client itself has the port closed*

- **Tools**
  - CovertTCP
  - ICMP Shell
  - 007 Shell
- The best way around a firewall will always be a compromised internal machine

## <u>How to detect a Honeypot</u>
*Probe services running on them; Ports that show a service is available, but **deny a three-way handshake may indicate that the system is a honeypot***.

* **Layer 7 (Application)** - Examine latency of responses from server
* **Layer 4 (Transport)** - Examine the TCP windows size, looing for continuous Acknowledgement of incoming packets even when the windows size is set to 0.
* **Layer 2 (Data Link)** - If you are on the same network as the honeypot, **look for MAC addresses** in packets that indicate the presence of a **'Black Hole'** (`0:0:f:ff:ff:ff`)

> ⚠️  **The exam will not cover every information presented, but is good to have a general idea.**

* If Honeypot is virtualized, look for the vendor assigned MAC address ranges as published by IEEE.
* If Honeypot is the **Honeyd** type, use time based TCP fingerprinting methods to detect
* Detecting **User-Mode Linux (UML) honeypot**, analyze `proc/mounts`, `proc/interrupts` and `proc/cmdline` which would have UML specific settings and information.
* Detecting Sebek-based honeypots, Sebek will log everything that is accessed via `read()` **before** sending to the network, causing congestion that can be an indicator.
* Detecting **snort_inline honeypots**, analyze the outgoing packets by capturing the snort_inline modified packets through another
