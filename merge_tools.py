#!/usr/bin/env python3
"""
Merge organized tools into existing repository structure
"""

import os
import re
from pathlib import Path

# Mapping of organized files to repository directories
DIRECTORY_MAPPING = {
    'ai-research_tools.md': 'ai-research/tools.md',
    'car-hacking_tools.md': 'car-hacking/tools.md',
    'cloud-resources_tools.md': 'cloud-resources/tools.md',
    'cracking-passwords_tools.md': 'cracking-passwords/tools.md',
    'cryptography-and-pki_tools.md': 'cryptography-and-pki/tools.md',
    'dfir_tools.md': 'dfir/tools.md',
    'exploit-development_tools.md': 'exploit-development/tools.md',
    'game-hacking_tools.md': 'game-hacking/tools.md',
    'honeypots-honeynets_tools.md': 'honeypots-honeynets/tools.md',
    'iot-hacking_tools.md': 'iot-hacking/tools.md',
    'linux-hardening_tools.md': 'linux-hardening/tools.md',
    'mobile-security_tools.md': 'mobile-security/tools.md',
    'networking_tools.md': 'networking/tools.md',
    'osint_tools.md': 'osint/tools.md',
    'post-exploitation_tools.md': 'post-exploitation/tools.md',
    'recon_tools.md': 'recon/tools.md',
    'reverse-engineering_tools.md': 'reverse-engineering/tools.md',
    'social-engineering_tools.md': 'social-engineering/tools.md',
    'threat-intelligence_tools.md': 'threat-intelligence/tools.md',
    'vulnerability-scanners_tools.md': 'vulnerability-scanners/tools.md',
    'web-application-testing_tools.md': 'web-application-testing/tools.md',
    'windows_tools.md': 'windows/tools.md',
    'wireless-resources_tools.md': 'wireless-resources/tools.md'
}

def read_existing_tools(filepath):
    """Read existing tools from a file"""
    if not os.path.exists(filepath):
        return set(), ""
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    
    # Extract URLs from existing content
    pattern = r'\]\((.*?)\)'
    urls = set(re.findall(pattern, content))
    
    return urls, content

def merge_tools(base_dir, organized_dir):
    """Merge organized tools into repository structure"""
    
    stats = {
        'files_created': 0,
        'files_updated': 0,
        'tools_added': 0,
        'duplicates_skipped': 0
    }
    
    for organized_file, target_path in DIRECTORY_MAPPING.items():
        organized_filepath = os.path.join(organized_dir, organized_file)
        target_filepath = os.path.join(base_dir, target_path)
        
        if not os.path.exists(organized_filepath):
            print(f"Warning: {organized_filepath} not found")
            continue
        
        # Read organized tools
        with open(organized_filepath, 'r', encoding='utf-8') as f:
            organized_content = f.read()
        
        # Extract tool entries
        pattern = r'- \[.*?\]\(.*?\)'
        new_tools = re.findall(pattern, organized_content)
        
        # Check if target directory exists
        target_dir = os.path.dirname(target_filepath)
        if not os.path.exists(target_dir):
            print(f"Warning: Directory {target_dir} does not exist, skipping...")
            continue
        
        # Read existing tools
        existing_urls, existing_content = read_existing_tools(target_filepath)
        
        # Filter out duplicates
        tools_to_add = []
        for tool in new_tools:
            url_match = re.search(r'\]\((.*?)\)', tool)
            if url_match:
                url = url_match.group(1)
                if url not in existing_urls:
                    tools_to_add.append(tool)
                    stats['tools_added'] += 1
                else:
                    stats['duplicates_skipped'] += 1
        
        if not tools_to_add:
            print(f"No new tools to add to {target_path}")
            continue
        
        # Create or update file
        if not os.path.exists(target_filepath):
            # Create new file
            category_name = os.path.basename(target_dir).replace('-', ' ').title()
            content = f"# {category_name} Tools\n\n"
            content += "This is a curated list of tools for this category.\n\n"
            content += "---\n\n"
            content += "\n".join(tools_to_add)
            content += "\n"
            
            with open(target_filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            
            stats['files_created'] += 1
            print(f"Created {target_path} with {len(tools_to_add)} tools")
        else:
            # Append to existing file
            with open(target_filepath, 'a', encoding='utf-8') as f:
                f.write("\n## Additional Tools\n\n")
                f.write("\n".join(tools_to_add))
                f.write("\n")
            
            stats['files_updated'] += 1
            print(f"Updated {target_path} with {len(tools_to_add)} new tools")
    
    return stats

def main():
    base_dir = '/Users/omar/Documents/GitHub/h4cker'
    organized_dir = os.path.join(base_dir, 'organized_tools')
    
    print("Merging organized tools into repository structure...")
    print("=" * 60)
    
    stats = merge_tools(base_dir, organized_dir)
    
    print("\n" + "=" * 60)
    print("Merge Statistics:")
    print(f"  Files created: {stats['files_created']}")
    print(f"  Files updated: {stats['files_updated']}")
    print(f"  Tools added: {stats['tools_added']}")
    print(f"  Duplicates skipped: {stats['duplicates_skipped']}")
    print("\nMerge complete!")

if __name__ == '__main__':
    main()



