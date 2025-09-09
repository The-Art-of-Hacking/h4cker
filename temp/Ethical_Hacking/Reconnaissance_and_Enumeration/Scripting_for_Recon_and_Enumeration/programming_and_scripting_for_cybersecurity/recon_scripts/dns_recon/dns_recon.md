# DNS Reconnassaince

## DNSRECON
* [dnsrecon](https://github.com/darkoperator/dnsrecon) - DNS Enumeration Script created by Carlos Perez (darkoperator)

Reverse lookup for IP range:
`./dnsrecon.rb -t rvs -i 10.1.1.1,10.1.1.50`

Retrieve standard DNS records:
`./dnsrecon.rb -t std -d example.com`

Enumerate subdornains:
`./dnsrecon.rb -t brt -d example.com -w hosts.txt`

DNS zone transfer:
`./dnsrecon -d example.com -t axfr`


## Parsing NMAP Reverse DNS Lookup

`nmap -R -sL -Pn -dns-servers dns svr ip range | awk '{if( ($1" "$2" "$3)=="NMAP scan report")print$5" "$6}' | sed 's/(//g' | sed 's/)//g' dns.txt `
