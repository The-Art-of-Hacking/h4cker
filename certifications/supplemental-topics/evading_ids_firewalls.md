# Techniques for Evading IDS

1. **Traffic Obfuscation**:
   - **Encryption**: Encrypting traffic can prevent IDS from inspecting the payload. For example, using tools like **Stunnel** or **OpenVPN** to encrypt data streams.
   - **Encoding**: Encoding payloads in formats like Base64 or using URL encoding can obscure the content. For example, encoding an SQL injection payload to bypass detection filters.

2. **Fragmentation**:
   - **Packet Fragmentation**: Breaking malicious payloads into smaller packets can evade detection by causing IDS to miss reassembled payloads. Techniques like IP fragmentation or TCP segmentation can be used.

3. **Polymorphism and Metamorphism**:
   - **Polymorphic Code**: Altering the code structure without changing its functionality to evade signature-based detection. For example, changing variable names or code layout.
   - **Metamorphic Code**: Completely rewriting the code to avoid signature detection. This involves transforming the code into a different form while maintaining the same behavior.

4. **Protocol Manipulation**:
   - **Protocol Tunneling**: Encapsulating malicious traffic within legitimate protocols. For instance, using HTTP or DNS tunneling to bypass IDS inspection.
   - **Protocol Abuses**: Exploiting protocol features to hide malicious payloads. For example, using malformed packets or unusual protocol behaviors.

# Techniques for Evading Firewalls

1. **Port Knocking**:
   - **Description**: A technique where an attacker sends a sequence of connection attempts to closed ports. If the correct sequence is detected, the firewall temporarily opens a port for the attacker.

2. **IP Spoofing**:
   - **Description**: Forging the source IP address to make traffic appear as if it comes from a trusted source. This can bypass IP-based filtering rules in firewalls.

3. **Tunneling**:
   - **Description**: Encapsulating malicious traffic within a legitimate protocol or using VPNs to bypass firewall rules. Techniques like SSH tunneling or VPNs can obscure the real nature of the traffic.

4. **Use of Allowed Ports**:
   - **Description**: Exploiting commonly allowed ports (e.g., HTTP on port 80) to deliver malicious payloads. This involves disguising the payload as legitimate traffic to bypass firewall filtering.
