import dns.resolver

def get_mx_record(domain):
    try:
        result = dns.resolver.resolve(domain, 'MX')
        for rdata in result:
            print(f'MX Record: {rdata.exchange.to_text()} with priority {rdata.preference}')
    except dns.resolver.NoAnswer:
        print(f"No MX records found for domain {domain}")
    except dns.resolver.NXDOMAIN:
        print(f"The domain {domain} does not exist")
    except Exception as e:
        print(f"An error occurred: {e}")

# Replace 'websploit.org' with the domain you are interested in
get_mx_record('websploit.org')
