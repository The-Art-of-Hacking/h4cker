#!/bin/bash
# bruteforce subdomains
# Use a wordlist of your choice. I am using dnscan's wordlist in this example

for domain in $(cat /usr/share/wordlists/dnscan/subdomains-100.txt);
do host $domain.h4cker.org;sleep 2;done | grep has | sort -u
