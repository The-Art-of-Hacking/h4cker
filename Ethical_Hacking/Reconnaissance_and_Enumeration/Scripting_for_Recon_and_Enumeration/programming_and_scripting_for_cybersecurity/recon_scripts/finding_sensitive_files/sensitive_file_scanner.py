#!/usr/bin/env python3
"""
Script Name: sensitive_file_scanner.py
Author: Omar Santos
Version: 0.1
Description:
    This script scans a specified directory for sensitive files based on file extensions and patterns.
    It is designed to be used on Linux systems. The script will output the paths of any matching
    sensitive files found in the specified directory and its subdirectories.

Dependencies/Prerequisites:
    - Python 3.x
    - No additional libraries are required.
"""

import os
import sys
import fnmatch

# List of sensitive file extensions and patterns to search for
sensitive_extensions = ['.key', '.pem', '.pgp', '.p12', '.pfx', '.csv']
sensitive_patterns = ['*password*', '*secret*', '*private*', '*confidential*']

# Function to check if the file matches sensitive file patterns
def is_sensitive_file(file_name):
    for pattern in sensitive_patterns:
        if fnmatch.fnmatch(file_name, pattern):
            return True

    _, file_extension = os.path.splitext(file_name)
    if file_extension in sensitive_extensions:
        return True

    return False

# Function to scan for sensitive files in the specified directory
def scan_directory(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            if is_sensitive_file(file):
                print(f"Sensitive file found: {os.path.join(root, file)}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 sensitive_file_scanner.py <directory>")
        sys.exit(1)

    search_directory = sys.argv[1]

    if not os.path.isdir(search_directory):
        print(f"Error: {search_directory} is not a valid directory")
        sys.exit(1)

    print(f"Scanning {search_directory} for sensitive files...")
    scan_directory(search_directory)
