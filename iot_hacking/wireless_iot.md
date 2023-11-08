# Wireless IoT Protocols and Implementations

| Protocol            | Frequency      | Range           | Data Rate        | Security Features                                              | Common Use Cases                         |
|---------------------|----------------|-----------------|------------------|----------------------------------------------------------------|------------------------------------------|
| Zigbee              | 2.4 GHz        | 10-100 meters   | 250 kbps         | AES-128 encryption, application layer security                | Home automation, smart energy            |
| Z-Wave              | 800-900 MHz    | 30-100 meters   | 9.6-100 kbps     | AES-128 encryption, application layer security                | Home automation, healthcare              |
| Wi-Fi               | 2.4 & 5 GHz    | 50+ meters      | Up to 6000 Mbps  | WPA3, WPA2, WEP, AES encryption, Enterprise security options  | High bandwidth applications, home networks |
| Bluetooth (incl. BLE) | 2.4 GHz        | 1-100 meters    | 1-3 Mbps (BLE)   | AES-128 encryption, application layer security, ECDH for key exchange | Wearables, healthcare, smart homes        |
| LoRaWAN             | Various (sub-GHz) | 2-5 km (urban), 15+ km (rural) | 0.3-50 kbps     | AES-128 encryption, end-to-end encryption                    | Smart cities, agricultural sensors       |
| Sigfox              | Sub-GHz        | 30-50 km        | 100-600 bps      | AES-128 encryption                                            | Low-power applications, asset tracking   |
| NB-IoT              | Sub-GHz        | 1-10 km         | 250 kbps         | E2E encryption, SIM-based security, secure boot               | Smart meters, smart city infrastructure  |
| LTE-M (LTE Cat-M1)  | Sub-GHz        | 1-10 km         | 1 Mbps           | E2E encryption, SIM-based security, secure boot               | Wearables, vehicle tracking              |
| Thread              | 2.4 GHz        | 10-30 meters    | 250 kbps         | AES encryption, secure mesh networking, device authentication | Connected home, security systems         |
| MQTT                | -              | Depends on network | Depends on network | TLS/SSL support, username/password, ACLs for permissions    | Remote sensors, home automation, messaging |
| CoAP                | -              | Depends on network | Depends on network | DTLS for security, supports TLS for TCP                      | Smart homes, energy management           |

- **Frequency**: The radio frequency at which the protocol operates.
- **Range**: The typical communication range between devices.
- **Data Rate**: The maximum achievable data transmission speed.
- **Security Features**:
  - **AES-128 encryption**: A symmetric key encryption standard that provides good security.
  - **WPA3/WPA2**: Security protocols for Wi-Fi networks, with WPA3 being the latest and most secure.
  - **ECDH**: Elliptic Curve Diffie-Hellman, a secure key exchange protocol.
  - **SIM-based security**: Utilizes the SIM card for secure key storage and authentication.
  - **Secure boot**: Ensures the device boots using only software that is trusted by the device manufacturer.
  - **TLS/SSL**: Protocols for securing data communications over networks.
  - **DTLS**: Datagram Transport Layer Security, a derivative of TLS designed for datagram protocols.
  - **ACLs**: Access Control Lists, which specify which users or system processes are granted access to objects.

