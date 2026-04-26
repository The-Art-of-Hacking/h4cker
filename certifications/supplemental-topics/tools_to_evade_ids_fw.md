# Tools to Evade IDS, IPS, and Firewalls

There are various techniques and tools that can be used to evade these security measures. Below is a summary of some of the most common methods and tools for evading IDS, IPS, and firewalls.

#### Techniques for Evasion

1. **TTL Manipulation**:
   - Sending packets with a Time-To-Live (TTL) value that allows them to reach the IDS/IPS but not the final destination can trick the system into ignoring subsequent packets with the same sequence but malicious content. 
   - **Nmap Option**: `--ttl <value>` [1].

2. **Avoiding Signatures**:
   - Adding garbage data to packets to avoid matching IDS/IPS signatures.
   - **Nmap Option**: `--data-length 25` [1].

3. **Fragmented Packets**:
   - Fragmenting packets so that if the IDS/IPS cannot reassemble them, they will pass through undetected.
   - **Nmap Option**: `-f` [1][4].

4. **Invalid Checksum**:
   - Sending packets with invalid checksums, which are often ignored by sensors for performance reasons but rejected by the final host.
   - Example: A packet with the RST flag and an invalid checksum [1].

5. **Uncommon IP and TCP Options**:
   - Using uncommon flags and options in IP and TCP headers that might be ignored by the IDS/IPS but accepted by the destination host [1].

6. **Overlapping Fragments**:
   - Creating overlapping fragments that are reassembled differently by the IDS/IPS and the final host, resulting in different interpretations of the packet [1].

7. **Decoy Scans**:
   - Using decoy IP addresses to mask the real source of the scan, making it difficult for the IDS/IPS to trace the attacker.
   - **Nmap Option**: `-D <decoy1,decoy2,...>` [4].

8. **Source IP and Port Spoofing**:
   - Spoofing the source IP address or port to make the traffic appear as if it is coming from a trusted source.
   - **Nmap Options**: `-S <source IP>`, `-g <source port>` [4].

9. **Timing Options**:
   - Adjusting the timing of packet transmission to avoid detection by IDS/IPS.
   - **Nmap Timing Options**: `T0` (Paranoid), `T1` (Sneaky), `T2` (Polite), `T3` (Normal), `T4` (Aggressive), `T5` (Insane) [4].

#### Tools for Evasion

1. **Nmap**:
   - A versatile tool that offers various options for evading IDS/IPS and firewall detection, including packet fragmentation, decoy scans, and timing adjustments [1][4].

2. **Hping3**:
   - A packet crafting tool that allows full control over packet flags, which can be used to bypass IDS/IPS and firewalls by setting uncommon flags [3].

3. **Custom Scripts**:
   - Writing custom scripts to craft and send packets with specific characteristics designed to evade detection [3].

4. **Fragrouter**:
   - https://www.kali.org/tools/fragrouter/.

These techniques and tools highlight the importance of understanding the capabilities and limitations of traditional IDS, IPS, and firewalls, as well as the need for ongoing updates and configurations to protect against evolving evasion strategies.

References:
[1] https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network/ids-evasion
[2] https://karsyboy.github.io/CEHv10_Ultimate_Study_Guide/Module%2012%20-%20Evading%20IDS,%20FIrewalls,%20and%20Honeypots.html
[3] https://www.reddit.com/r/cybersecurity/comments/cgmput/is_it_possible_to_bypass_firewalls_or_evade/
[4] https://security.stackexchange.com/questions/121900/how-can-the-nmap-tool-be-used-to-evade-a-firewall-ids
[5] https://www.reddit.com/r/cybersecurity/comments/19cjvd7/what_idsips_tools_have_you_implemented_at_work/
