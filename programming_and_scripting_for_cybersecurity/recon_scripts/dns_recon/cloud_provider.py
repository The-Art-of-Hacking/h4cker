'''
This script takes a domain as input and returns the IP address of the domain, the organization 
owning the IP address, and whether the IP address belongs to a major cloud provider.
Author: Omar Santos @santosomar
'''

# Import the necessary modules
import socket
import whois

def get_domain_ip(domain):
    '''
    get domain IP address
    :param domain: domain
    :return: ip_address
    '''
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return None

def get_whois_info(ip_address):
    '''
    get whois information
    :param ip_address: ip_address
    :return: whois information
    '''
    try:
        w = whois.whois(ip_address)
        return w
    except whois.WhoisException:
        return None

def is_major_cloud_provider(whois_info):
    '''
    check if the IP address belongs to a major cloud provider
    :param whois_info: whois_info
    :return: True or False
    '''
    cloud_providers = ["Amazon", "Azure", "Microsoft", "Google", "Digital Ocean", "Alibaba", "Oracle"]
    for provider in cloud_providers:
        if provider.lower() in whois_info.lower():
            return True
    return False

def main(domain):
    '''
    main function
    :param domain: domain
    :return: None
    '''
    ip_address = get_domain_ip(domain)
    if ip_address:
        print(f"The IP address of {domain} is {ip_address}")
        whois_info = get_whois_info(ip_address)
        if whois_info and whois_info.org:
            print(f"The organization owning the IP is: {whois_info.org}")
            if is_major_cloud_provider(str(whois_info.org)):
                print(f"The IP address belongs to a major cloud provider.")
            else:
                print(f"The IP address does not belong to a known major cloud provider.")
        else:
            print(f"Could not retrieve WHOIS information.")
    else:
        print(f"Could not find IP address for {domain}.")

if __name__ == "__main__":
    domain = input("""Cloud Checker example by Omar Santos.
Please enter a domain: """)
    main(domain)
