# quick script to get IP addresses from a predefined domain list text file.

#create a file called domains.txt and exec the following one-liner script.
for url in $(cat domains.txt); do host $url; done | grep "has address" | cut -d " " -f 4 | sort -u
