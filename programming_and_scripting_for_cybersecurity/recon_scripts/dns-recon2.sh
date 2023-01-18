#!/bin/bash
# bruteforce subdomains
# Use a wordlist of your choice. I am using dnscan's wordlist in this example

for domain in $(cat /usr/share/wordlists/amass/fierce_hostlist.txt); do host $domain.h4cker.org; done  | grep -v NXDOMAIN | sort -u
