# General Rules for Avoiding Detection During Scanning
When performing network scanning, especially when trying to avoid detection, there are several general rules and best practices you can follow. The specific approach often depends on the scope, permissions, and environment, but here are some guidelines that can help minimize the risk of detection:


1. **Adjust Timing Options**:
   - **Timing Templates**: Use Nmap timing templates to control the speed of the scan. The `-T0` to `-T5` options range from "Paranoid" (slowest, least likely to be detected) to "Insane" (fastest, most likely to be detected). Commonly, `-T2` (Polite) or `-T3` (Normal) are used for less aggressive scans.
   - **Randomize Targets** (`-iR`): Randomize the order of the IP addresses being scanned to avoid triggering intrusion detection system (IDS) signatures based on sequential scanning.

2. **Reduce Scan Intensity**:
   - **Scan Fewer Ports**: Instead of scanning all 65,535 ports, limit the scan to common ports or a specific subset using `-p`.
   - **Slow Down the Scan**: Increase the delay between probes using `--scan-delay` or `--max-scan-delay` to reduce the likelihood of triggering rate-based detection mechanisms.

3. **Evade Firewalls and IDS/IPS**:
   - **Fragment Packets** (`-f`): Fragment packets to bypass simple packet filtering.
   - **Source Port Manipulation** (`--source-port`): Set the source port to a common, trusted port to bypass some firewall rules.
   - **Decoy Scans** (`-D`): Use decoy IP addresses to mask the origin of the scan.

4. **Use Legitimate Traffic Patterns**:
   - **Blend with Normal Traffic**: Conduct scans during times of high network activity to blend in with legitimate traffic patterns.
   - **Use Legitimate User Agents and Headers**: If scanning web applications, use legitimate user agents and headers to mimic normal user behavior.


## Practical Example Using Nmap

```bash
nmap -sS -p 22,80,443 -T2 --scan-delay 100ms -D RND:10 -f -Pn target-ip
```

- **`-sS`**: SYN scan
- **`-p 22,80,443`**: Scan only specific ports
- **`-T2`**: Use the "Polite" timing template
- **`--scan-delay 100ms`**: Introduce a 100 ms delay between probes
- **`-D RND:10`**: Use 10 random decoy IP addresses
- **`-f`**: Fragment packets
- **`-Pn`**: Treat all hosts as online, skip host discovery

