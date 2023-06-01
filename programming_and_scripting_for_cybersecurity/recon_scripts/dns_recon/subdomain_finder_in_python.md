# How to Create a Sub-Domain Finder in Python

The following is a sample Python script to find subdomains using DNS. This script is using the `dns.resolver` module from the `dnspython` library. If you don't have the library installed, you can install it using pip:

```
pip3 install dnspython
```

The following is the Python script that can be used to find subdomains for a given domain using a provided wordlist file:

```
import dns.resolver
import argparse

def load_subdomains(file_path):
    with open(file_path, 'r') as file:
        subdomains = file.read().splitlines()
    return subdomains

def find_subdomains(domain, subdomains):
    found_subdomains = []
    resolver = dns.resolver.Resolver()

    for subdomain in subdomains:
        target = f'{subdomain}.{domain}'
        try:
            answers = resolver.resolve(target, 'A')
            found_subdomains.append((target, [str(answer) for answer in answers]))
        except dns.resolver.NXDOMAIN:
            pass
        except Exception as e:
            print(f'Error resolving {target}: {e}')
    return found_subdomains

def main():
    parser = argparse.ArgumentParser(description='Find subdomains using DNS')
    parser.add_argument('domain', type=str, help='Domain to search for subdomains')
    parser.add_argument('wordlist', type=str, help='Path to subdomain wordlist file')
    args = parser.parse_args()

    subdomains = load_subdomains(args.wordlist)
    found_subdomains = find_subdomains(args.domain,
```


- Import necessary libraries: The script imports the dns.resolver module from the dnspython library, as well as the argparse module to handle command-line arguments.
- `load_subdomains(file_path)`: This function takes a file path as input and reads the file, splitting the content by lines to get a list of subdomains. It returns the list of subdomains.
- `find_subdomains(domain, subdomains)`: This function takes a domain and a list of subdomains as input. It initializes a DNS resolver object and iterates through the subdomains list, attempting to resolve each subdomain by appending it to the domain and performing a DNS lookup for the 'A' record (IPv4 address). If the lookup is successful, the subdomain and its corresponding IP addresses are added to the found_subdomains list. If the lookup fails with a `dns.resolver.NXDOMAIN` exception, the subdomain does not exist, and the script continues to the next subdomain. For other exceptions, an error message is printed. The function returns the `found_subdomains` list containing the successfully resolved subdomains and their IP addresses.
- `main()`: This function sets up the command-line argument parser, which expects two arguments: the target domain and the path to the subdomain wordlist file. It then calls `load_subdomains()` to load the subdomains from the wordlist file, and `find_subdomains()` to perform the DNS lookups.
