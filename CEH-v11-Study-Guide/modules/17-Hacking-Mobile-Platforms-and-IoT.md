# Hacking Mobile Platforms and IoT

# <u>A) Mobile Platform Hacking</u>

- **Three Main Avenues of Attack**
  - **Device Attacks** - browser based, SMS, application attacks, rooted/jailbroken devices
  - **Network Attacks** - DNS cache poisoning, rogue APs, packet sniffing
  - **Data Center (Cloud) Attacks** - databases, photos, etc.

<br>

- **OWASP Top 10 Mobile Risks:**
  - ![owasp-mobile](https://www.nowsecure.com/wp-content/uploads/2016/10/OWASP-Mobile-Top-10.png)

<br>

- **M1 - Improper Platform Usage** - Misuse of features or security controls (Android intents, TouchID, Keychain)

- **M2 - Insecure Data Storage** - Improperly stored data and data leakage

- **M3 - Insecure Communication** - Poor handshaking, incorrect SSL, clear-text communication

- **M4 - Insecure Authentication** - Authenticating end user or bad session management

- **M5 - Insufficient Cryptography** - Code that applies cryptography to an asset, but is insufficient (does NOT include SSL/TLS)

- **M6 - Insecure Authorization** - Failures in authorization (access rights)

- **M7 - Client Code Quality** - Catchall for code-level implementation problems

- **M8 - Code Tampering** - Binary patching, resource modification, dynamic memory modification

- **M9 - Reverse Engineering** - Reversing core binaries to find problems and exploits

- **M10 - Extraneous Functionality** - Catchall for backdoors that were inadvertently placed by coders

## <u>Mobile Platforms</u>

- **Android** - platform built by Google
  - **Rooting** - name given to the ability to have root access on an Android device
    - **Tools**
      - KingoRoot
      - TunesGo
      - OneClickRoot
      - MTK Droid
- **iOS** - platform by Apple
  - **Jailbreaking** - different levels of rooting an iOS device
    - **Tools**
      - evasi0n7
      - GeekSn0w
      - Pangu
      - Redsn0w
      - Absinthe
      - Cydia
    - **Techniques**
      - **Untethered** - kernel remains patched after reboot, with or without a system connection
      - **Semi-Tethered** - reboot no longer retains patch; must use installed jailbreak software to re-jailbreak
      - **Tethered** - reboot removes all jailbreaking patches; phone may get in boot loop requiring USB to repair
    - **Types**
      - **Userland exploit** - found in the system itself; gains root access; does not provide admin; can be patched by Apple
      - **iBoot exploit** - found in bootloader called iBoot; uses vulnerability to turn codesign off; semi-tethered; can be patched
      - **BootROM exploit** - allows access to file system, iBoot and custom boot logos; found in device's first bootloader; cannot be patched
- **App Store attacks** - since some App stores are not vetted, malicious apps can be placed there
- **Phishing attacks** - mobile phones have more data to be stolen and are just as vulnerable as desktops
- **Android Device Administration API** - allows for security-aware apps that may help
- **Bring Your Own Device** (BYOD) - dangerous for organizations because not all phones can be locked down by default
- **Mobile Device Management** - like group policy on Windows; helps enforce security and deploy apps from enterprise
  - MDM solutions include XenMobile, IBM, MaaS360, AirWatch and MobiControl
- **Bluetooth attacks** - if a mobile device can be connected to easily, it can fall prey to Bluetooth attacks
  - **Discovery mode** - how the device reacts to inquiries from other devices
    - **Discoverable** - answers all inquiries
    - **Limited Discoverable** - restricts the action
    - **Nondiscoverable** - ignores all inquiries
  - **Pairing mode** - how the device deals with pairing requests
    - **Pairable** - accepts all requests
    - **Nonpairable** - rejects all connection requests

## <u>Mobile Attacks</u>
All other attacks presented on previous chapter are suceptible to mobile devices too attacks like session hijacking, browser vulnerabilities, XSS, email, SMS, phone, OS/Apps bugs, excessive permissions and so on. Vulnerabilities on connection (Bluetooth, WiFi, NFC), encryption.


- **SMS Phishing (Smishing)** - sending texts with malicious links
  - People tend to trust these more because they happen less
  - **Trojans Available to Send**
    - Obad
    - Fakedefender
    - TRAMPS
    - ZitMo
  - **Spyware**
    - Mobile Spy
    - Spyera
- Mobile platform features such as Find my iPhone, Android device tracking and the like can be hacked to find devices, etc.
- **Mobile Attack Platforms** - tools that allow you to attack from your phone
  - Network Spoofer
  - DroidSheep
  - Nmap

### <u>Bluetooth:</u>
- **Bluetooth Attacks**
  - **Bluesmacking** - Denial of service against device
  - **Bluejacking** - Sending unsolicited messages
  - **Bluesniffing** - Attempt to discover Bluetooth devices
  - **Bluebugging** - Remotely using a device's features
  - **Bluesnarfing** - Theft of data from a device
  - **Blueprinting** - Collecting device information over Bluetooth

- **Bluetooth Attack Tools**
  - **BlueScanner** - finds devices around you
  - **BT Browser** - another tool for finding and enumerating devices
  - **Bluesniff** and **btCrawler** - sniffing programs with GUI
  - **Bloover** - can perform Bluebugging
  - **PhoneSnoop** - good spyware option for Blackberry
  - **Super Bluetooth Hack** - all-in-one package that allows you to do almost anything

## Improving Mobile Security
- Always check OS and Apps are up to date
- Screen Locks + Passwords
- Secure Wireless comunication
- No Jailbreaking or Rooting
- Don't store sensitive information on mobile (like confidential information from company)
- Remote desktop (e.g. Citrix)
- Use Official app stores
- Anti-virus
- Remote wipe option
- Remote management
- Remote tracking

⚠️ Companies should use **MDM policies** to accomplish mobile security.


# <u>B) IoT Architecture</u>

### **- What is IoT?**
***The Internet of Things (IoT)** describes the network of physical objects—“things”—that are embedded with sensors, software, and other technologies for the purpose of connecting and exchanging data with other devices and systems over the internet.*

- Traditional fields of embedded systems, wireless sensor networks, control systems, automation (including home and building automation), and others all contribute to enabling the Internet of things. 

- ![iot](https://www.researchgate.net/profile/Akram_Hakiri/publication/281896657/figure/fig1/AS:391492888743939@1470350586428/High-level-IoT-architecture.png)

- **Three Basic Components**
  - Sensing Technology
  - IoT gateways
  - The cloud

### **Methods of Communicating**
*IoT connectivity boils down to how things connect to each other. Can be wired, wireless, 4G LTE, Bluetooth, GPS, LoRa, mesh networking, RFID, WiFi, Zigbee and Z-wave.*

  - **Device to Device** - Direct communication between two devices.
  - **Device to Cloud** - Communicates directly to a cloud service.
  - **Device to Gateway** - Communicate to a centralized gateway that gathers data and then sends it to an application server based in the cloud.
  - **Back-End Data Sharing** - Used to scale the device to cloud model to allow for multiple devices to interact withone or more application servers.

> ⚠️ **Zigbee** and **Z-Wave** is a wireless mesh networking protocol popular in home automation. 

### **Edge Computing**
*Edge Computing is a distributed computing paradigm in which processing and computation are performed mainly on classified device nodes known as smart devices or edge devices as opposed to processed in a centralized cloud environment or data centers.*

<p align="center">
<img width=70%"" src="https://www.xenonstack.com/images/blog/2019/11/edge-computing-services-solutions-xenonstack.png" />
</p>

- It helps to provide server resources, data analysis, and artificial intelligence to data collection sources and cyber-physical sources like smart sensors and actuators.

> ⚠️ **Edge computing** handling data by pushing into the cloud. **Fog Computing** is more like keep things locally.

### **Multi-Layer Architecture of IoT**
- **Edge Technology Layer** - consists of sensors, RFID tags, readers and the devices
- **Access Gateway Layer** - first data handling, message identification and routing
- **Internet Layer** - crucial layer which serves as main component to allow communication
- **Middleware Layer** - sits between application and hardware; handles data and device management, data analysis and aggregation
- **Application Layer** - responsible for delivery of services and data to the user

### **IoT Technology Protocols**
- **Short-Range Wireless:**
  - Bluetooth Low-energy (BLE)
  - Light-Fidelity (Li-Fi)
  - Near Field Communication (NFC)
  - QR Codes & Barcodes
  - Radio-frequency Identification (RFID)
  - Wi-fi / Direct
  - Z-wave
  - Zigbee
- **Medium-Range Wireless:**
  - Ha-Low
  - LTE-Advanced
- **Long-Range Wireless:**
  - Low-power Wide-area Networking (LPWAN)
  - LoRaWAN
  - Sigfox
  - Very Smart Aperture Terminal (VSAT)
  - Cellular
- **Wired Communications:**
  - Ethernet 
  - Power-Line Communication (PLC)
  - Multimedia over Coax Alliance (MoCA)

### **IoT Operating Systems**
- **RIOT OS** - Embedded systems, actuator boards, sensors; is energy efficient
- **ARM Mbed OS** - Mostly used on wearables and other low-powered devices
- **RealSense OS X** - Intel's depth sensing version; mostly found in cameras and other sensors
- **Nucleus RTOS** - Used in aerospace, medical and industrial applications
- **Brillo** - Android-based OS; generally found in thermostats
- **Contiki** - OS made for low-power devices; found mostly in street lighting and sound monitoring
- **Zephyr** - Option for low-power devices and devices without many resources
- **Ubuntu Core** - Used in robots and drones; known as "snappy"
- **Integrity RTOS** - Found in aerospace, medical, defense, industrial and automotive sensors
- **Apache Mynewt** - Used in devices using Bluetooth Low Energy Protocol

### **Geofencing**
*Uses GPS and RFID technologies to create a virtual geographic boundary, like around your home property. A response is then triggered any time a mobile device enters or leaves the area.*

### **Grid Computing**
Reduces costs by maximizing existing resources. This is accomplished with **multiple machines together to solve a specific problem.**

### **Analytics of Things (AoT)**
- The analysis of IoT data, which is the data being generated by IoT sensors and devices.

### **Industrial IoT (IIoT)**
![iiot](https://i1.wp.com/intellinium.io/wp-content/uploads/2016/12/iot_edited.png?w=800&ssl=1)

*The industrial internet of things (IIoT) refers to the extension and use of the internet of things (IoT) in industrial sectors and applications. With a strong focus on machine-to-machine (M2M) communication, big data, and machine learning, the IIoT enables industries and enterprises to have better efficiency and reliability in their operations.*

- **The IIoT encompasses industrial applications, including robotics, medical devices, and software-defined production processes.**

## <u>IoT Vulnerabilities and Attacks:</u>

### **OWASP Top 10 IoT Vulnerabilities (2014)**
- **I1 - Insecure Web Interface** 
  - Problems such as account enumeration, weak credentials, and no account lockout
- **I2 - Insufficient Authentication/Authorization** 
  - Assumes interfaces will only be exposed on internal networks and thus is a flaw
- **I3 - Insecure Network Services** 
  - May be susceptible to buffer overflow or DoS attacks
- **I4 - Lack of Transport Encryption/Integrity Verification** 
  - Data transported without encryption
- **I5 - Privacy Concerns** 
  - Due to collection of personal data
- **I6 - Insecure Cloud Interface** 
  - Easy-to-guess credentials make enumeration easy
- **I7 - Insecure Mobile Interface** 
  - Easy-to-guess credentials on mobile interface
- **I8 - Insufficient Security Configurability** 
  - Cannot change security which causes default passwords and configuration
- **I9 - Insecure Software/Firmware** 
  - Lack of a device to be updated or devices that do not check for updates
- **I10 - Poor Physical Security** 
  - Because of the nature of devices, these can easily be stolen

---

### **OWASP Top 10 IoT Vulnerabilities (2018)**

- **1. Weak, guessable, or hardcoded passwords**
  - Use of easily bruteforced, publicly available, or unchangeable credentials, including backdoors in firmware or client software that grants unauthorized access to deployed systems.

- **2. Insecure network services**
  - Unneeded or insecure network services running on the device itself, especially those exposed to the internet, that compromise the confidentiality, integrity/authenticity, or availability of information or allow unauthorized remote control…

- **3. Insecure ecosystem interfaces**
  - Insecure web, backend API, cloud, or mobile interfaces in the ecosystem outside of the device that allows compromise of the device or its related components. Common issues include a lack of authentication/authorization, lacking or weak encryption, and a lack of input and output filtering.

- **4. Lack of secure update mechanism**
  - Lack of ability to securely update the device. This includes lack of firmware validation on device, lack of secure delivery (un-encrypted in transit), lack of anti-rollback mechanisms,
and lack of notifications of security changes due to updates.
- **5. Use of insecure or outdated components**
  - Use of deprecated or insecure software components/libraries that could allow the device to be compromised. This includes insecure customization of operating system platforms, and the use of third-party software or hardware components from a compromised supply chain.
- **6. Insufficient privacy protection**
  - User’s personal information stored on the device or in the ecosystem that is used insecurely, improperly, or without permission. 
- **7. Insecure data transfer and storage**
  - Lack of encryption or access control of sensitive data anywhere within the ecosystem, including at rest, in transit, or during processing.
- **8. Lack of device management**
  - Lack of security support on devices deployed in production, including asset management, update management, secure decommissioning, systems monitoring, and response capabilities.
- **9. Insecure default settings**
  - Devices or systems shipped with insecure default settings or lack the ability to make the system more secure by restricting operators from modifying configurations.
- **10. Lack of physical hardening**
  - Lack of physical hardening measures, allowing potential attackers to gain sensitive information that can help in a future remote attack or take local control of the device.
---



## <u>Common IoT Attack Areas</u>
1. Device memory containing credentials
2. Device / Ecosystem Access Control
3. Device Physical Interfaces / Fimrware extraction
4. Device web interface
5. Device Firmware
6. Device network services
7. Devices administrative interface(s)
8. Unencrypted Local data storage
9. Cloud interface(s)
10. Device update mechanism(s)
11. Insecure API's (vendor & thir-party)
12. Mobile application
13. Confidentiality and Integrity issues across the ecosystem
14. Network traffic

## <u>IoT Threats</u>
1. **DDoS Attack**
2. **HVAC System attacks** - Attacks on HVAC systems
3. **Rolling code attack** - Used to steal cars; The ability to jam a key fob's communications, steal the code and then create a subsequent code
4. **BlueBorne attack** - Attacks against Bluetooth devices
5. **Jamming attack**
6. **Remote access via backdoors**
7. **Remote access via unsecured protocols** such as TELNET
8. **Sybil attack** - Uses multiple forged identities to create the illusion of traffic; happens when a insecure computer is hijacked to claim multiple identities.
9. **Rootkits / Exploit kits**
10. **Ransomware**


> ⚠️ **Other attacks already enumerated in other sections still apply such as MITM, ransomware, side channel, replay attack etc.**

## <u>IoT Hacking Methodology</u>

### **Steps**:
1. **Information Gathering** - gathering information about the devices; 
    - **Tools**:
      - Shodan
      - Censys
      - Thingful
      - Google 

2. **Vulnerability Scanning** - same as normal methodology - looks for vulnerabilities
    - **Tools:**
      - Nmap
      - Multi-ping
      - RIoT Vulnerability Scanner
      - Foren6 (traffic sniffer)
      - beSTORM

3. **Launching Attacks**
    - **Tools:**
      - RFCrack
      - Attify Zigbee Framework
      - HackRF
      - Firmalyzer

4. **Gaining Access** - same objectives as normal methodology

5. **Maintaining Access** - same objectives as normal methodology
---
## Countermeasures to help secure IoT devices:

1. Firmware updates
2. Block ALL unecessary ports
3. Disable insecure access protocols such as TELNET
4. Only use encrypted communication protocols
5. Use strong passwords
6. Encrypt ALL data and communications coming into, being stored in and leaving the device
7. Use account lockout
8. Configuration management and baselining of devices along with compliance monitoring
9. Use multi-factor authentication
10. Disable UPnP
