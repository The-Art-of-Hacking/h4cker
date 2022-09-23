# Hacking Wireless Networks

## <u>Concepts and Terminology</u>

### BSSID
**Basic Service Set Identifier (BSSID)** - **MAC address** of the wireless access point 


### SSID
**Service Set Identifier (SSID)** - Is a name of a network; text word (<= 32 char) that identifies network; provides no security.

### ESSID
**Extended Service Set Identifier (ESSID)** - An extended basic service set (ESS) consists of all of the BSSs in the network. For all practical purposes, the ESSID identifies the same network as the SSID does. **The term SSID is used most often.**

- **802.11 Series** - defines the standards for wireless networks
- **802.15.1** - Bluetooth
- **802.15.4** - Zigbee - low power, low data rate, close proximity ad-hoc networks
- **802.16** - WiMAX - broadband wireless metropolitan area networks


- **Basic Service Set (BSS)** - communication between a single AP and its clients

- **Orthogonal Frequency-Division Multiplexing (OFDM)**  - carries waves in various channels.

- **Multiple-Input Multiple-Output (MIMO)** - MIMO uses multiple antennas at the transmitting and receiving sides to improve spectral efficiency by capitalizing on transmission and spatial diversities along with multipath propagation.

- **ISM Band** - The ISM radio bands are portions of the radio spectrum reserved internationally for industrial, scientific and medical (ISM) purposes other than telecommunications. Examples of applications for the use of radio frequency (RF) energy in these bands include radio-frequency process heating, microwave ovens, and medical diathermy machines.

### **DSSS and FHSSS spectrums:**
![dsss](https://www.researchgate.net/profile/Edi_Kurniawan/publication/329286286/figure/fig1/AS:698501847580681@1543547226994/Frequency-spectrum-of-a-DSSS-b-FHSS.png)
- **Direct-Sequence Spread Spectrum (DSSS)** - Combines all available waveforms into a single purpose. 

- **Frequency-hopping spread spectrum (FHSS)** - Is a method of transmitting radio signals by rapidly changing the carrier frequency among many distinct frequencies occupying a large spectral band.


- **Spectrum Analyzer** - verifies wireless quality, detects rogue access points and detects attacks

### **Wireless Standards**:
| Wireless Standard | Operating Speed (Mbps) | Frequency (GHz) | Modulation Type |
|-------------------|------------------------|-----------------|-----------------|
| 802.11a           | 54 Mbps                    | 5 GHz               | OFDM            |
| 802.11b           | 11 Mbps                    | 2.4 GHz            | DSSS            |
| 802.11g           | 54 Mbps                    | 2.4 GHz            | OFDM and DSSS   |
| 802.11n           | 600 Mbps                   | 2.4-5 GHz          | OFDM            |
| 802.11ac          | 1000 Mbps                  | 5 GHz              | QAM             |


### **Authentication**
- **Three Types of Authentication**
  - **Open System** - no authentication
  - **Shared Key Authentication** - authentication through a shared key (password)
  - **Centralized Authentication** - authentication through something like **RADIUS**
- **Association** is the act of connecting; **authentication** is the act of identifying the client
Antenna Types:

> ⚠️ **RADIUS** is a networking protocol, operating on port 1812, that provides centralized Authentication, Authorization, and Accounting (AAA or Triple A) management for users who connect and use a network service.

### **Antenna Types:**
<p align="center">
<img width="92%" src="https://mk0gcgablogq2ifx558u.kinstacdn.com/wp-content/uploads/2016/06/Wireless-Antenna.jpg" />
</p>

* **Omnidirectional antenna**
	* Signals goes on every direction like a dome.
* **Dipole antenna**
  * Goes on two directions.
* **Directional antenna**
	* Long individual beam, increased distances. 
	* **Yagi antenna**
		- Very directional and high gain.
	* **Parabolic antenna**
		- Focus the signal to a single point.
* **Patch Graphic antenna**
	* Half Omni (e.g stick to the wall the get one side signals).


## <u>Wireless Encryption Schemes</u>

## Wireless Security
### **WEP** - Wireless Equivalency Privacy

* 64/128 bit RC4 ICV 
* **RC4** - Rivest Cipher 4 Stream Cipher Algorithm<br>
* **ICV** - Integrity Check Value

> ⚠️ Very old and insecure

### **WPA** - Wi-Fi Protected Access

* Uses RC4 with TKIP (Temporal Key Integrity Protocol)
	- Initialization Vector (IV) is larger and an encrypted hash
	- Every packet gets a unique 128-bit encryption key
* **Personal | WPA-PSK**
	- TKIP + **PSK**
	- 64/128 bit **RC4 MIC**
	- Everyone uses the same 256-bit key
* **Enterprise | WPA-802.1X**
	- TKIP + **RADIUS**
	- 64/128 bit **RC4 MIC**
	- Authenticates users individually with an authentication server (e.g., RADIUS)

#### About TKIP - Temporal Key Integrity Protocol
- Mixed the keys
	- Combines the secret root key with the IV
- Adds sequence counter
	- Prevents replay attacks
- Implements a 64-bit Message Integrity Check
	- Protecting against tampering
- TKIP has it's own set of vulnerabilities
	- Deprecated in the 802.11-2012 standard

### **WPA2** - Wi-Fi Protected Access v2

* **802.11i** IEEE standard
* Enterprise
	* CCMP + **RADIUS**
	* 128 bit **AES MIC Encryption**

* Personal
	* CCMP + **PSK** (Pre Shared Key)
	* 128 bit **AES MIC Encryption**

- AES (Advanced Encryption Standard) replaced RC4
- CCMP (Counter Mode with Cipher Block Chaining Message Authentication Code Protocol) replaced TKIP

* **About CCMP**
	- Uses AES for data confidentiality
	- 128-bit key and a 128-bit block size
	- Requires additional computing resources
	- **CCMP provides Data confidentiality (AES), authentication, and access control**

<p align="center">
<img src="https://gist.githubusercontent.com/Samsar4/62886aac358c3d484a0ec17e8eb11266/raw/a6960e23a5da2cc3c689416f284376f35d599c58/encryption2.png" />
</p>

| Wireless Standard | Encryption | IV Size (Bits) | Key Length (Bits) | Integrity Check |
|-------------------|------------|----------------|-------------------|-----------------|
| WEP               | RC4        | 24             | 40/104            | CRC-32          |
| WPA               | RC4 + TKIP | 48             | 128               | Michael/CRC-32  |
| WPA2              | AES-CCMP   | 48             | 128               | CBC-MAC (CCMP)  |

---

## <u>Wireless Hacking</u>

- **Threats**
  - Access Control Attacks
  - Integrity Attacks
  - Confidentiality Attacks
  - Availability Attacks
  - Authentication Attacks

- **Network Discovery**
  - Wardriving, warflying, warwalking, etc.
  - Tools such as WiFiExplorer, WiFiFoFum, OpenSignalMaps, WiFinder
  - **WIGLE** - map for wireless networks
  - **NetStumbler** - tool to find networks
  - **Kismet** - wireless packet analyzer/sniffer that can be used for discovery
  	- Works without sending any packets (passively)
  	- Can detects access points that have not been configured
  	- Works by channel hopping
  	- Can discover networks not sending beacon frames
  	- Ability to sniff packets and save them to  a log file (readable by Wireshark/tcpdump)
  - **NetSurveyor** - tool for Windows that does similar features to NetStumbler and Kismet
  	- Doesn't require special drivers

- **WiFi Adapter**
  - AirPcap is mentioned for Windows, but isn't made anymore
  - **pcap** - driver library for Windows
  - **libpcap** - driver library for Linux

## <u>Wireless Attacks</u>

- **Rogue Access Point** - Unauthorized access point plugged into a wired one. (Can be accidental)
  - Tools for Rogue AP: **Wi-Fi Pumpkin**, **Wi-Fi Pineapple**
- **Evil Twin** - Is a Rogue AP tha is broadcasting **the same (or very similar) SSID**.
  - Also known as a mis-association attack
- **Honeyspot** - faking a well-known hotspot with a rogue AP
- **Ad Hoc Connection Attack** - connecting directly to another phone via ad-hoc network
  - Not very successful as the other user has to accept connection
- **DoS Attack** - either sends de-auth packets to the AP or jam the wireless signal
  - With a de-auth, you can have the users connect to your AP instead if it has the same name
  - Jammers are very dangerous as they are illegal
- **MAC Filter** - only allows certain MAC addresses on a network
  - Easily broken because you can sniff out MAC addresses already connected and spoof it
    - Tools for spoofing include: **SMAC** and **TMAC**

## <u>Wireless Encryption Attacks</u>

### **WEP Cracking**
- To crack the WEP key for an access point, we need to gather lots of initialization vectors (IVs). Attackers can use injection to speed up the process by replaying packets


- **Process:**
  1. Start the wireless interface in monitor mode on the specific AP channel
  2. Test the injection capability of the wireless device to the AP
  3. Use aireplay-ng to do a fake authentication with the access point
  4. Start airodump-ng on AP channel with a BSSID filter to collect the new unique IVs
  5. Start aireplay-ng in ARP request replay mode to inject packets
  6. Run aircrack-ng to crack key using the IVs collected

### **WPA/WPA2 Cracking**
- Much more difficult than WEP
- Uses a constantly changing temporal key and user-defined password
- **Key Reinstallation Attack** (KRACK) - replay attack that uses third handshake of another device's session
- Most other attacks are simply brute-forcing the password

- **Process:**
  1. Start monitoring and find the BSSID (e.g: using `airodump-ng`)
  2. Start monitoring only the BSSID with .cap output file
  3. The goal is to grab a WPA handshake; The attacker can wait to some client to connect to grab the handshake /or use a deauth attack to deauthenticate a client to make him/her connect again.
  4. Start `aircrack-ng` using a good wordlist to brute force the .cap file that you recorded on step 2.


### **Tools:**
- **Aircrack-ng Suite** - is a complete suite of tools to assess WiFi network security.
  1. **Monitoring:** Packet capture and export of data to text files for further processing by third party tools.
  2. **Attacking:** Replay attacks, deauthentication, fake access points and others via packet injection.
  3. **Testing:** Checking WiFi cards and driver capabilities (capture and injection).
      - **`airodump-ng`** - Airodump-ng is used for packet capturing of raw 802.11 frames and is particularly suitable for collecting WEP IVs (Initialization Vector) for the intent of using them with aircrack-ng. 
      - **`airmon-ng`** - Used to enable monitor mode on wireless interfaces.
      - **`aireplay-ng`** - Is used to inject frames (arp replay, deauthentication attack, etc).
      - **`aircrack-ng`** - Is an 802.11 WEP and WPA/WPA2-PSK key cracking program.

- **Cain and Abel** - Sniffs packets and cracks passwords (may take longer)
  - Relies on statistical measures and the PTW technique to break WEP
- **Wifite** - Is an automated wireless attack tool.
- **KisMAC** - MacOS tool to brute force WEP or WPA 
  passwords
- **Fern WiFi Cracker** 
- **WEPAttack**
- **WEPCrack**
- **Portable Penetrator**
- **Elcomsoft's Wireless Security Auditor**
- Methods to crack include **PTW**, **FMS**, and **Korek** technique


## <u>Bluetooth Attacks</u>
  - **Bluesmacking** - Denial of service against device
  - **Bluejacking** - Sending unsolicited messages
  - **Bluebugging** - Remotely using a device's features
  - **Bluesnarfing** - Theft of data from a device

## <u>Wireless Sniffing</u>

- Very similar to sniffing a wired network
- **Tools**
  - **NetStumbler**
  - **Kismet** - is a network detector, packet sniffer, and IDS for 802.11 wireless LANs.
  - **OmniPeek** - provides data like Wireshark in addition to network activity and monitoring
  - **AirMagnet WiFi Analyzer Pro** - sniffer, traffic analyzer and network-auditing suite
  - **WiFi Pilot**

## Protecting Wireless Networks - Best practices

-  Use 802.11i
    - WPA2
    - AES encryption
    - MAC Filtering with ACL *(It's not a final solution, hackers can circumvent)*
    - Disable SSID broadcast *(It's not a final solution, hackers can circumvent)*
    - Use VPN in case of home office (connecting externally)

 ⚠️ Warnings of Public / Free Wi-Fi
- Session hijacking
- Rogue APs
- Evil Twins
