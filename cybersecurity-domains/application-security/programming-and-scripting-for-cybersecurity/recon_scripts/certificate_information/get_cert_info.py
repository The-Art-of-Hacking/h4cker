'''
This script takes a domain as input and returns the SSL certificate information of the domain.
Author: Omar Santos @santosomar
'''

# Import the necessary modules 
import ssl
import socket
from pprint import pprint
import argparse

def get_certificate_info(hostname, port=443):
    '''
    get certificate information
    :param hostname: hostname
    :param port: port
    :return: None
    '''
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
    conn.settimeout(3.0)

    try:
        conn.connect((hostname, port))
        cert = conn.getpeercert()
        pprint(cert)
    except Exception as e:
        print(f"Could not retrieve certificate information: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    # Parse the command line arguments
    parser = argparse.ArgumentParser(description='Get SSL certificate information of a domain.')
    parser.add_argument('domain', type=str, help='Domain name to get the certificate information')
    parser.add_argument('--port', type=int, default=443, help='Port number (default: 443)')
    
    args = parser.parse_args()
    
    get_certificate_info(args.domain, args.port)
