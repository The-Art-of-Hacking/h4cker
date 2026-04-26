'''
This script checks for weak crypto implementations in a website.
Author: Omar Santos @santosomar
'''

# Import the necessary modules
import ssl
import socket
import argparse

# List of weak cipher suites
# Change this list to include the weak cipher suites that you want to check
WEAK_CIPHER_SUITES = [
    'aNULL', 'eNULL', 'EXPORT', 'DES', 'MD5', 'PSK', 'RC4', 'SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1', 'SEED'
]

def check_weak_crypto(hostname, port=443):
    '''
    check for weak crypto implementations
    :param hostname: hostname
    :param port: port
    :return: None
    '''
    for cipher in WEAK_CIPHER_SUITES:
        context = ssl.SSLContext(ssl.PROTOCOL_SSL23)
        context.set_ciphers(cipher)

        try:
            conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname)
            conn.connect((hostname, port))
            print(f"Weak cipher suite detected: {cipher}")
        except Exception:
            pass
        finally:
            conn.close()

if __name__ == "__main__":
    '''
    The following are the arguments required for the script to run successfully
    -d, --domain: domain name to check
    -p, --port: port number (default: 443)
    '''
    parser = argparse.ArgumentParser(description='Check for weak crypto implementations in a website')
    parser.add_argument('domain', type=str, help='Domain name to check')
    parser.add_argument('--port', type=int, default=443, help='Port number (default: 443)')
    
    args = parser.parse_args()
    
    check_weak_crypto(args.domain, args.port)
