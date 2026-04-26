# macOS Hardening and Security Resources

This directory contains resources, guides, and tools for hardening and securing macOS systems, as well as detecting and responding to security compromises.

## Contents

### Detection and Response
- **[detecting-compromise.md](detecting-compromise.md)** - Comprehensive guide for identifying rootkits and system compromise on macOS
  - Quick triage commands for immediate threat assessment
  - Process and memory analysis techniques
  - Kernel extension and rootkit detection methods
  - File system and persistence analysis
  - Network and system monitoring approaches
  - Security tools and verification procedures
  - Advanced detection techniques
  - Incident response checklist
  - Preventive hardening measures
  - References and resources

## Overview

macOS, while generally considered secure by design, is not immune to security threats. Modern macOS malware and rootkits have become increasingly sophisticated, requiring comprehensive detection and response strategies.

### Key Security Features of macOS

1. **System Integrity Protection (SIP)** - Protects critical system files and directories
2. **Gatekeeper** - Verifies downloaded applications before first run
3. **XProtect** - Built-in malware scanning
4. **Notarization** - Apple's malware scanning service for distributed software
5. **Secure Boot** - Ensures only trusted OS software runs at startup (Apple Silicon)
6. **FileVault** - Full disk encryption
7. **TCC (Transparency, Consent, and Control)** - Privacy controls for app permissions

### Common Threat Vectors

- **Kernel Extensions (KEXTs)** - Though deprecated, legacy systems may still be vulnerable
- **System Extensions** - Modern replacement for KEXTs, but still a potential attack vector
- **Launch Agents/Daemons** - Persistence mechanisms frequently abused by malware
- **Dylib Hijacking** - Library injection and path manipulation attacks
- **Browser Extensions** - Malicious or compromised extensions
- **Supply Chain Attacks** - Compromised legitimate software updates
- **Social Engineering** - Tricking users into disabling security features

## Tools and Resources

### Objective-See Tools (Free)
Patrick Wardle's excellent collection of macOS security tools:
- **KnockKnock** - Scans for persistent malware
- **BlockBlock** - Monitors persistence locations
- **KextViewr** - Kernel extension viewer
- **LuLu** - Firewall application
- **ReiKey** - Keyboard event monitor
- **Netiquette** - Network monitor
- **OverSight** - Microphone and webcam monitor
- **What's Your Sign** - Code signing verification

### Command Line Tools
- **osquery** - SQL-powered operating system instrumentation
- **rkhunter** - Rootkit detection (via Homebrew)
- **OSSEC** - Host-based intrusion detection system
- **Santa** - Binary authorization system (Google)

### Forensics Tools
- **Volatility** - Memory forensics framework
- **OSXPMem** - macOS memory acquisition
- **rekall** - Advanced memory forensics

## Best Practices

### For System Administrators

1. **Enable core security features**
   - Keep System Integrity Protection (SIP) enabled
   - Enable FileVault disk encryption
   - Set firmware password on Intel Macs
   - Enable Gatekeeper and XProtect
   - Configure firewall appropriately

2. **Maintain security posture**
   - Keep macOS and all software updated
   - Regularly review installed applications
   - Monitor system and security logs
   - Audit persistence mechanisms periodically
   - Document baseline system state

3. **Implement monitoring**
   - Deploy endpoint detection and response (EDR) solutions
   - Enable and review security audit logs
   - Monitor network traffic
   - Track system changes

### For Security Researchers

1. **Test in isolated environments** - Use virtual machines or dedicated test systems
2. **Document findings thoroughly** - Maintain detailed notes and screenshots
3. **Follow responsible disclosure** - Report vulnerabilities appropriately
4. **Stay current** - macOS security landscape evolves rapidly
5. **Understand the platform** - Learn macOS internals and architecture

### For Incident Responders

1. **Preserve evidence** - Don't shutdown the system immediately
2. **Collect volatile data first** - Memory, running processes, network connections
3. **Create forensic images** - Use appropriate tools and methodology
4. **Follow chain of custody** - Document all actions
5. **Analyze systematically** - Follow established incident response procedures

## Learning Resources

### Books
- "macOS and iOS Internals" by Jonathan Levin
- "The Mac Hacker's Handbook" by Charlie Miller and Dino Dai Zovi
- "macOS Support Essentials" by Apple Education

### Online Resources
- [Apple Platform Security Guide](https://support.apple.com/guide/security/welcome/web)
- [Objective-See Blog](https://objective-see.com/blog.html)
- [Mac4n6 (macOS Forensics)](https://www.mac4n6.com/)
- [MITRE ATT&CK - macOS Matrix](https://attack.mitre.org/matrices/enterprise/macos/)

### Training and Certifications
- Apple Certified Support Professional (ACSP)
- SANS FOR518: Mac and iOS Forensic Analysis
- Offensive Security macOS Exploitation courses

## Contributing

Contributions are welcome! If you have additional detection techniques, tools, or resources to share, please consider contributing to this repository.

## Legal and Ethical Considerations

⚠️ **Important Notice**

The information and tools in this directory are provided for:
- Educational purposes
- Authorized security testing
- Legitimate incident response
- System administration

**Do not use these tools or techniques on systems you do not own or have explicit written authorization to test.**

Unauthorized access to computer systems is illegal in most jurisdictions. Always:
- Obtain proper authorization before testing
- Respect privacy and confidentiality
- Follow organizational policies and procedures
- Comply with applicable laws and regulations

## Version Information

This guide is maintained for current and recent macOS versions. Some commands and techniques may vary across different macOS versions:

- **macOS 15 (Sequoia)** - Latest
- **macOS 14 (Sonoma)** - Current
- **macOS 13 (Ventura)** - Supported
- **macOS 12 (Monterey)** - Legacy support
- **macOS 11 (Big Sur)** - Legacy support

Older versions may have different security features and command syntax.

## Related Resources

- [Linux Hardening](../linux-hardening/) - Similar resources for Linux systems
- [DFIR Resources](../dfir/) - Digital forensics and incident response tools
- [Threat Hunting](../threat-hunting/) - Proactive threat hunting resources
- [Windows Resources](../windows/) - Windows security resources

---

*This directory is part of the [h4cker repository](https://github.com/The-Art-of-Hacking/h4cker) maintained by Omar Santos.*
