import re

# Define a list of known malicious IPs
malicious_ips = ['192.168.1.10', '10.0.0.5']

# Function to search through a log file
def search_log(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()
    
    for log in logs:
        # Extract IP using regex (assuming a standard Apache log format)
        ip = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', log)
        
        # Check if the IP exists in the malicious IPs list
        if ip and ip[0] in malicious_ips:
            print(f"Potential threat found! IP address {ip[0]} found in log.")

# Path to the log file
log_file_path = 'path/to/your/logfile.log'

# Start the search
search_log(log_file_path)
