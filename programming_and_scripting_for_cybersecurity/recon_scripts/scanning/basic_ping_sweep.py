# A simple script to perform a ping sweep of the 
# Websploit (websploit.org) containers in the 
# 10.6.6.0/24 network.

import subprocess

# Define the network to scan
network = "10.6.6.0/24"

# Use the 'ping' command to scan the network
for i in range(1, 255):
    ip = "10.6.6." + str(i)
    result = subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.PIPE)
    if result.returncode == 0:
        print(ip + " is up")
    else:
        print(ip + " is down")

# This script uses a for loop to iterate through all possible IP addresses in the network
# (from 10.6.6.1 to 10.6.6.254) and uses the ping command to check if the host is up or down. 
# The -c option specifies the number of pings to send, 
# and the -W option specifies the timeout in seconds.
