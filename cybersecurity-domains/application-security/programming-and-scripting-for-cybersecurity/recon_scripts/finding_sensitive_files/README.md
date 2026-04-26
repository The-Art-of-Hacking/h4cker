# Sensitive File Scanner

This script scans a specified directory for sensitive files based on file extensions and patterns. It is designed to be used on Linux systems.

## Requirements

- Python 3.x

## Usage

To use the script, follow the steps below:

1. Save the script to a file named `sensitive_file_scanner.py`.

2. Run the script with the directory you want to scan as an argument:

```
python3 sensitive_file_scanner.py /path/to/scan
```

The script will output the paths of any matching sensitive files found in the specified directory and its subdirectories.

## Customization
You can customize the list of sensitive file extensions and patterns by modifying the sensitive_extensions and sensitive_patterns lists in the sensitive_file_scanner.py script. Add or remove extensions and patterns based on your specific requirements.

```
sensitive_extensions = ['.key', '.pem', '.pgp', '.p12', '.pfx', '.csv']
sensitive_patterns = ['*password*', '*secret*', '*private*', '*confidential*']
```

## Disclaimer
This script is provided for educational and informational purposes only. The author (Omar Santos) and future contributors are not responsible for any misuse, damage, or unintended consequences caused by the use of this script. Always ensure you have proper authorization before scanning any system or network.

