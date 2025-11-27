#!/usr/bin/env python3
"""
Tool Organization Script
Parses more_tools.md and new_tools.md and organizes tools into appropriate directories
"""

import re
import os
from collections import defaultdict

# Category mappings based on keywords in tool descriptions
CATEGORIES = {
    'web-application-testing': [
        'xss', 'sqli', 'sql injection', 'web scanner', 'web application', 'burp', 
        'web vulnerability', 'web security', 'web recon', 'web crawl', 'web spider',
        'xxe', 'ssrf', 'csrf', 'lfi', 'rfi', 'directory traversal', 'web shell',
        'web fuzzer', 'web pentest', 'web exploit', 'http', 'https', 'web firewall',
        'waf', 'api security', 'api test', 'rest api', 'graphql'
    ],
    'recon': [
        'reconnaissance', 'osint', 'subdomain', 'dns enum', 'information gathering',
        'footprint', 'discovery', 'enumeration', 'asset discovery', 'domain enum',
        'network mapping', 'host discovery', 'service discovery', 'shodan', 'censys'
    ],
    'exploit-development': [
        'exploit', 'buffer overflow', 'rop', 'shellcode', 'payload', 'metasploit',
        'exploit framework', 'vulnerability exploit', 'poc', 'proof of concept',
        'exploit generation', 'fuzzing', 'fuzzer', 'afl', 'exploit kit'
    ],
    'post-exploitation': [
        'post exploitation', 'privilege escalation', 'lateral movement', 'persistence',
        'credential dump', 'mimikatz', 'lsass', 'password dump', 'hash dump',
        'domain admin', 'active directory', 'bloodhound', 'kerberos', 'ntlm'
    ],
    'mobile-security': [
        'android', 'ios', 'mobile', 'apk', 'mobile app', 'mobile security',
        'mobile pentest', 'mobile exploit', 'frida', 'objection', 'mobile forensic'
    ],
    'wireless-resources': [
        'wifi', 'wireless', 'wpa', 'wep', 'wps', '802.11', 'aircrack', 'wireless security',
        'wireless attack', 'deauth', 'handshake', 'wireless pentest', 'bluetooth', 'ble'
    ],
    'networking': [
        'network', 'packet', 'pcap', 'wireshark', 'tcpdump', 'network traffic',
        'network analysis', 'network monitor', 'network scan', 'port scan', 'nmap',
        'network forensic', 'network security', 'sniff', 'packet capture'
    ],
    'dfir': [
        'forensic', 'incident response', 'memory analysis', 'disk forensic',
        'volatility', 'artifact', 'timeline', 'evidence', 'forensic analysis',
        'malware analysis', 'reverse engineering', 'threat hunting', 'edr', 'siem'
    ],
    'cloud-resources': [
        'aws', 'azure', 'gcp', 'cloud', 's3', 'ec2', 'kubernetes', 'k8s', 'docker',
        'container', 'cloud security', 'cloud pentest', 'cloud enum', 'serverless',
        'lambda', 'cloud native', 'devops', 'devsecops'
    ],
    'osint': [
        'osint', 'social media', 'email', 'username', 'people search', 'breach',
        'leak', 'dox', 'social engineering', 'phishing', 'maltego', 'spiderfoot',
        'theHarvester', 'twitter', 'facebook', 'linkedin', 'instagram'
    ],
    'cracking-passwords': [
        'password crack', 'hash crack', 'brute force', 'dictionary attack',
        'hashcat', 'john', 'hydra', 'password recovery', 'hash', 'rainbow table',
        'wordlist', 'password spray', 'credential stuff'
    ],
    'cryptography-and-pki': [
        'crypto', 'encryption', 'decryption', 'cipher', 'ssl', 'tls', 'certificate',
        'pki', 'rsa', 'aes', 'cryptanalysis', 'hash function', 'digital signature',
        'openssl', 'gpg', 'pgp'
    ],
    'reverse-engineering': [
        'reverse engineering', 'disassembler', 'decompiler', 'ida', 'ghidra',
        'binary analysis', 'malware reverse', 'unpacking', 'obfuscation',
        'deobfuscation', 'radare', 'x64dbg', 'ollydbg', 'debugger'
    ],
    'iot-hacking': [
        'iot', 'embedded', 'firmware', 'hardware', 'uart', 'jtag', 'spi', 'i2c',
        'router', 'smart device', 'iot security', 'iot pentest', 'firmware analysis',
        'binwalk', 'embedded security'
    ],
    'linux-hardening': [
        'linux hardening', 'linux security', 'selinux', 'apparmor', 'linux audit',
        'linux baseline', 'cis benchmark', 'linux compliance', 'system hardening'
    ],
    'windows': [
        'windows', 'powershell', 'windows security', 'windows exploit',
        'windows pentest', 'windows privilege', 'uac bypass', 'windows defender',
        'windows audit', 'registry', 'windows service'
    ],
    'vulnerability-scanners': [
        'vulnerability scanner', 'vuln scan', 'security scanner', 'nessus',
        'openvas', 'nexpose', 'qualys', 'acunetix', 'nikto', 'vulnerability assessment'
    ],
    'threat-intelligence': [
        'threat intelligence', 'ioc', 'indicator', 'threat feed', 'mitre att&ck',
        'threat hunting', 'cti', 'stix', 'taxii', 'yara', 'threat actor', 'apt'
    ],
    'honeypots-honeynets': [
        'honeypot', 'honeynet', 'deception', 'trap', 'cowrie', 'dionaea',
        'honeyd', 'honeypot framework'
    ],
    'social-engineering': [
        'social engineering', 'phishing', 'spear phish', 'pretexting', 'set',
        'social engineer toolkit', 'phishing framework', 'credential harvest',
        'phishing campaign', 'vishing', 'smishing'
    ],
    'car-hacking': [
        'car', 'vehicle', 'automotive', 'can bus', 'obd', 'vehicle security',
        'car hacking', 'automotive security'
    ],
    'game-hacking': [
        'game hack', 'game cheat', 'game mod', 'game security', 'anti-cheat',
        'game memory', 'cheat engine'
    ],
    'ai-research': [
        'ai', 'machine learning', 'ml', 'deep learning', 'neural network',
        'gpt', 'llm', 'openai', 'artificial intelligence', 'ai security',
        'adversarial', 'model security', 'prompt injection', 'ai red team'
    ],
    'docker-and-k8s-security': [
        'docker', 'kubernetes', 'k8s', 'container security', 'pod security',
        'helm', 'kube', 'container scan', 'image scan', 'docker security'
    ]
}

def extract_tools_from_file(filepath):
    """Extract tool entries from markdown file"""
    tools = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        
    # Match lines starting with "- [Tool Name - Description](URL)"
    pattern = r'- \[(.*?)\]\((.*?)\)'
    matches = re.findall(pattern, content)
    
    for match in matches:
        description = match[0]
        url = match[1]
        tools.append({
            'description': description,
            'url': url,
            'original': f'- [{description}]({url})'
        })
    
    return tools

def categorize_tool(tool):
    """Categorize a tool based on its description"""
    description_lower = tool['description'].lower()
    
    # Track all matching categories
    matches = []
    
    for category, keywords in CATEGORIES.items():
        for keyword in keywords:
            if keyword in description_lower:
                matches.append(category)
                break
    
    # Return primary category or 'more_tools' if no match
    if matches:
        return matches[0]
    return 'more_tools'

def organize_tools(tools):
    """Organize tools into categories"""
    categorized = defaultdict(list)
    
    for tool in tools:
        category = categorize_tool(tool)
        categorized[category].append(tool)
    
    return categorized

def generate_markdown_content(tools, title):
    """Generate markdown content for a category"""
    content = f"# {title}\n\n"
    content += "The following tools are organized for this category:\n\n"
    content += "---\n\n"
    
    for tool in sorted(tools, key=lambda x: x['description']):
        content += f"{tool['original']}\n"
    
    return content

def main():
    print("Starting tool organization...")
    
    # Read both files
    more_tools_path = '/Users/omar/Documents/GitHub/h4cker/more_tools.md'
    new_tools_path = '/Users/omar/Documents/GitHub/h4cker/new_tools.md'
    
    print(f"Reading {more_tools_path}...")
    more_tools = extract_tools_from_file(more_tools_path)
    print(f"Found {len(more_tools)} tools in more_tools.md")
    
    print(f"Reading {new_tools_path}...")
    new_tools = extract_tools_from_file(new_tools_path)
    print(f"Found {len(new_tools)} tools in new_tools.md")
    
    # Combine all tools
    all_tools = more_tools + new_tools
    print(f"Total tools to organize: {len(all_tools)}")
    
    # Remove duplicates based on URL
    seen_urls = set()
    unique_tools = []
    for tool in all_tools:
        if tool['url'] not in seen_urls:
            seen_urls.add(tool['url'])
            unique_tools.append(tool)
    
    print(f"Unique tools after deduplication: {len(unique_tools)}")
    
    # Categorize tools
    print("Categorizing tools...")
    categorized = organize_tools(unique_tools)
    
    # Print statistics
    print("\nCategorization Statistics:")
    for category, tools in sorted(categorized.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"  {category}: {len(tools)} tools")
    
    # Generate output files
    output_dir = '/Users/omar/Documents/GitHub/h4cker/organized_tools'
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"\nGenerating organized files in {output_dir}...")
    for category, tools in categorized.items():
        filename = f"{category}_tools.md"
        filepath = os.path.join(output_dir, filename)
        
        title = category.replace('-', ' ').title() + " Tools"
        content = generate_markdown_content(tools, title)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"  Created {filename} with {len(tools)} tools")
    
    print("\nOrganization complete!")
    print(f"Check the '{output_dir}' directory for organized tool lists.")

if __name__ == '__main__':
    main()



