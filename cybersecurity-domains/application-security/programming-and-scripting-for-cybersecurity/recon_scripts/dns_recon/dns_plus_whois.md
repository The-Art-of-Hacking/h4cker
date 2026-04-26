# DNS Resolution + WHOIS

During a penetration test, it is crucial to verify that the discovered hosts are within the defined scope. In today's landscape, where organizations often leverage cloud services to host their applications, it becomes essential to determine if a subdomain or hostname belongs to an application that is hosted outside of the organization's infrastructure. The following script can be immensely valuable in identifying whether a particular subdomain or hostname is associated with an application hosted in the cloud rather than being hosted internally by the organization.

```
import sys
import requests
import socket
import whois

def dns_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        print("IP Address: ", ip)
        return ip
    except socket.gaierror:
        print("DNS Lookup Failed")
        return None

def whois_lookup(ip):
    try:
        w = whois.whois(ip)
        print("OrgName: ", w.org)
        print("Address: ", w.address)
        print("RegDate: ", w.creation_date)
        print("NetRange: ", w.range)
        print("CIDR: ", w.cidr)
    except Exception as e:
        print("WHOIS Lookup Failed: ", str(e))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python passive_recon.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]

    # Perform DNS Lookup
    print("Performing DNS Lookup for", domain)
    ip_address = dns_lookup(domain)

    if ip_address:
        # Perform WHOIS Lookup
        print("\nPerforming WHOIS Lookup for", ip_address)
        whois_lookup(ip_address)
```

1. The script imports the necessary libraries and modules, including `sys`, `socket`, and `whois`.

2. The `dns_lookup` function takes a domain as input and performs a DNS lookup using the `socket.gethostbyname` method to obtain the IP address associated with the domain. It then prints the IP address and returns it.

3. The `whois_lookup` function takes an IP address as input and performs a WHOIS lookup using the `whois.whois` method. It retrieves the WHOIS information for the given IP address, including OrgName, Address, RegDate, NetRange, and CIDR. It then prints this information.

4. The `if __name__ == "__main__":` block is the main execution part of the script.

5. It first checks if the command-line argument count is not equal to 2 (indicating that a domain argument is missing). If so, it prints the usage information and exits the script.

6. The script retrieves the domain from the command-line argument.

7. It calls the `dns_lookup` function with the domain to perform the DNS lookup and obtain the IP address associated with the domain. The IP address is stored in the `ip_address` variable.

8. If an IP address is obtained successfully, the script calls the `whois_lookup` function with the IP address to perform the WHOIS lookup.

9. The `whois_lookup` function retrieves the WHOIS information for the IP address and prints the OrgName, Address, RegDate, NetRange, and CIDR information.

You can run the script by providing the domain name as a command-line argument, like this:

```
python passive_recon.py secretcorp.org
```

The script performs a DNS lookup to obtain the IP address associated with the domain, and then it performs a WHOIS lookup based on that IP address. At the end, it prints the OrgName, Address, RegDate, NetRange, and CIDR information obtained from the WHOIS lookup.

Please note that the effectiveness of the WHOIS lookup depends on the availability and accuracy of the WHOIS information for the given IP address.

  Then it prints the OrgName, Address, RegDate, NetRange, and CIDR information obtained from the WHOIS lookup.



