# Reconnaissance and Enumeration

This section covers the information gathering and enumeration phases of penetration testing, which form the foundation for identifying potential attack vectors.

## Overview

Reconnaissance and enumeration are critical first steps in any penetration test. These activities help identify the attack surface, discover services, and gather intelligence that will inform later exploitation attempts.

## Subdirectories

### [Information Gathering](./Information_Gathering/)
- Active vs passive reconnaissance techniques
- OSINT (Open Source Intelligence) sources and methods
- Network reconnaissance and protocol scanning
- Certificate transparency and search engine enumeration

### [Enumeration Techniques](./Enumeration_Techniques/)
- Operating system fingerprinting
- Service discovery and banner grabbing
- User, email, and share enumeration
- DNS, directory, and permissions enumeration

### [Scripting for Recon & Enumeration](./Scripting_for_Recon_and_Enumeration/)
- Automation using Bash, Python, and PowerShell
- Custom reconnaissance scripts and tools
- API integration for data gathering
- Parsing and analyzing collected data

### [Tools](./Tools/)
- Commercial and open-source reconnaissance tools
- Network scanning and enumeration utilities
- OSINT platforms and search engines
- Wireless reconnaissance tools

## Key Concepts

### Active vs Passive Reconnaissance
- **Passive**: Gathering information without directly interacting with target systems
- **Active**: Direct interaction with target systems to gather information

### Information Sources
- Social media platforms and professional networks
- Public databases and repositories
- DNS records and certificate logs
- Cached web pages and archived content

### Enumeration Targets
- Network services and protocols
- Web applications and APIs
- User accounts and email addresses
- File shares and directory structures

## Best Practices

1. **Start Passive** - Begin with passive reconnaissance to avoid detection
2. **Document Everything** - Keep detailed records of all discovered information
3. **Respect Scope** - Only gather information within the defined engagement scope
4. **Validate Data** - Cross-reference information from multiple sources
5. **Automate When Possible** - Use scripts to efficiently process large datasets
