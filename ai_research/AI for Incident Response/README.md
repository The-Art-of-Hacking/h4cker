# AI-Powered Log Analysis for Incident Response

This tool uses OpenAI's GPT-4o model to analyze security logs and identify potential threats, malicious activities, and indicators of compromise (IOCs).

## Features

- **Modern OpenAI Client**: Updated to use the latest OpenAI Python client (v1+)
- **Advanced AI Model**: Leverages GPT-4o for superior threat detection capabilities
- **Structured Analysis**: Returns JSON-formatted results with threat levels, IOCs, and recommendations
- **Comprehensive Detection**: Identifies various attack types including:
  - Brute force attacks
  - Privilege escalation attempts
  - Malware indicators
  - Suspicious network activity
  - Anomalous user behavior
- **Error Handling**: Robust error handling for file operations and API calls
- **Flexible Input**: Supports command-line arguments for different log files

## Installation

1. Install required dependencies:
```bash
pip3 install openai python-dotenv
```

2. Set up your OpenAI API key:
   - Create a `.env` file in the same directory
   - Add your API key: `OPENAI_API_KEY=your_api_key_here`

## Usage

### Basic Usage
```bash
python analyzing_logs.py
```
This will analyze the default `logs.txt` file.

### Custom Log File
```bash
python analyzing_logs.py /path/to/your/logfile.log
```

## Output Format

The tool provides structured analysis including:

- **Summary**: Brief overview of findings
- **Threat Level**: LOW/MEDIUM/HIGH/CRITICAL
- **Malicious Activity Detection**: Boolean indicator
- **Detailed Findings**: Specific threats with severity levels and recommendations
- **IOCs**: Extracted indicators including IPs, domains, file hashes, and user accounts
- **Security Recommendations**: Actionable steps to improve security posture

## Example Output

```
============================================================
🔍 CYBERSECURITY LOG ANALYSIS RESULTS
============================================================

📊 SUMMARY: Multiple security threats detected including brute force attacks and malware
🚨 THREAT LEVEL: HIGH
⚠️  MALICIOUS ACTIVITY: YES

🔎 DETAILED FINDINGS (3 items):

  1. BRUTE_FORCE_ATTACK
     Severity: HIGH
     Description: Multiple failed login attempts from IP 203.0.113.45
     Indicators: 203.0.113.45, failed_login_attempts
     Recommendations: Block IP address; Implement account lockout policies

🎯 INDICATORS OF COMPROMISE (IOCs):
  Ip Addresses: 203.0.113.45, 198.51.100.25
  Domains: suspicious-domain.evil.com
  File Hashes: malicious_payload.exe

💡 SECURITY RECOMMENDATIONS:
  1. Implement stronger authentication mechanisms
  2. Monitor network traffic for suspicious domains
  3. Regular malware scanning and quarantine procedures
```

## Security Best Practices

This tool follows cybersecurity best practices:
- Secure API key management using environment variables
- Structured output for integration with SIEM systems
- Comprehensive threat categorization
- Actionable security recommendations

## Author

Omar Santos (@santosomar)

## Updates

- **2024**: Updated to use OpenAI client v1+ with GPT-4o model
- Enhanced error handling and structured JSON output
- Improved cybersecurity-focused prompts and analysis
- Added comprehensive IOC extraction and threat categorization
