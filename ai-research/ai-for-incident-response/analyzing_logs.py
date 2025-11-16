'''
AI-powered log analysis for cybersecurity incident response
Analyzes logs from applications, firewalls, operating systems, and more to detect malicious activity.
Updated to use the latest OpenAI client (v1+) and GPT-4o model.
Author: Omar Santos, @santosomar
'''

# Import the required libraries
# pip3 install openai python-dotenv  
# Use the line above if you need to install the libraries
from dotenv import load_dotenv
from openai import OpenAI
import os
import json
import sys
from pathlib import Path

# Load the .env file
load_dotenv()

# Initialize the OpenAI client with the new v1+ syntax
client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

def analyze_logs(log_file_path='logs.txt'):
    """
    Analyze security logs using GPT-4o to identify potential threats and malicious activity.
    
    Args:
        log_file_path (str): Path to the log file to analyze
        
    Returns:
        dict: Structured analysis results
    """
    
    # Check if log file exists
    if not Path(log_file_path).exists():
        print(f"Error: Log file '{log_file_path}' not found.")
        return None
    
    try:
        # Read the log file
        with open(log_file_path, 'r', encoding='utf-8') as file:
            log_content = file.read()
        
        if not log_content.strip():
            print("Error: Log file is empty.")
            return None
        
        # Enhanced prompt for better cybersecurity analysis
        system_prompt = """You are a cybersecurity expert specializing in log analysis and incident response. 
        Analyze the provided logs and identify potential security threats, anomalies, and malicious activities.
        
        Provide your analysis in the following JSON format:
        {
            "summary": "Brief overview of findings",
            "threat_level": "LOW/MEDIUM/HIGH/CRITICAL",
            "malicious_activity_detected": true/false,
            "findings": [
                {
                    "type": "threat_type",
                    "severity": "LOW/MEDIUM/HIGH/CRITICAL", 
                    "description": "detailed description",
                    "indicators": ["list of IOCs or suspicious patterns"],
                    "recommendations": ["list of recommended actions"]
                }
            ],
            "iocs": {
                "ip_addresses": ["suspicious IPs"],
                "domains": ["suspicious domains"],
                "file_hashes": ["suspicious file hashes"],
                "user_accounts": ["suspicious user accounts"]
            },
            "recommendations": ["overall security recommendations"]
        }"""
        
        user_prompt = f"""Analyze the following security logs for potential threats and malicious activity:

{log_content}

Focus on:
- Failed authentication attempts and brute force attacks
- Unusual network connections or data transfers
- Privilege escalation attempts
- Malware indicators or suspicious file activities
- Anomalous user behavior patterns
- System compromise indicators"""

        # Generate the AI analysis using the latest OpenAI client
        response = client.chat.completions.create(
            model="gpt-4o",  # Using GPT-4o as it's the latest available model
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            max_tokens=4000,
            temperature=0.1,  # Lower temperature for more consistent analysis
            response_format={"type": "json_object"}  # Ensure JSON response
        )
        
        # Parse the response
        analysis_result = json.loads(response.choices[0].message.content)
        
        return analysis_result
        
    except FileNotFoundError:
        print(f"Error: Could not find log file '{log_file_path}'")
        return None
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse AI response as JSON: {e}")
        print("Raw response:", response.choices[0].message.content)
        return None
    except Exception as e:
        print(f"Error during log analysis: {e}")
        return None

def print_analysis_results(analysis):
    """
    Print the analysis results in a formatted, readable way.
    
    Args:
        analysis (dict): The analysis results from analyze_logs()
    """
    if not analysis:
        return
    
    print("=" * 60)
    print("🔍 CYBERSECURITY LOG ANALYSIS RESULTS")
    print("=" * 60)
    
    print(f"\n📊 SUMMARY: {analysis.get('summary', 'N/A')}")
    print(f"🚨 THREAT LEVEL: {analysis.get('threat_level', 'UNKNOWN')}")
    print(f"⚠️  MALICIOUS ACTIVITY: {'YES' if analysis.get('malicious_activity_detected') else 'NO'}")
    
    # Print findings
    findings = analysis.get('findings', [])
    if findings:
        print(f"\n🔎 DETAILED FINDINGS ({len(findings)} items):")
        for i, finding in enumerate(findings, 1):
            print(f"\n  {i}. {finding.get('type', 'Unknown').upper()}")
            print(f"     Severity: {finding.get('severity', 'Unknown')}")
            print(f"     Description: {finding.get('description', 'N/A')}")
            
            indicators = finding.get('indicators', [])
            if indicators:
                print(f"     Indicators: {', '.join(indicators)}")
            
            recommendations = finding.get('recommendations', [])
            if recommendations:
                print(f"     Recommendations: {'; '.join(recommendations)}")
    
    # Print IOCs
    iocs = analysis.get('iocs', {})
    if any(iocs.values()):
        print(f"\n🎯 INDICATORS OF COMPROMISE (IOCs):")
        for ioc_type, values in iocs.items():
            if values:
                print(f"  {ioc_type.replace('_', ' ').title()}: {', '.join(values)}")
    
    # Print overall recommendations
    recommendations = analysis.get('recommendations', [])
    if recommendations:
        print(f"\n💡 SECURITY RECOMMENDATIONS:")
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
    
    print("\n" + "=" * 60)

if __name__ == "__main__":
    # Allow specifying log file as command line argument
    log_file = sys.argv[1] if len(sys.argv) > 1 else 'logs.txt'
    
    print(f"🔍 Analyzing log file: {log_file}")
    print("🤖 Using GPT-4o for AI-powered threat detection...")
    
    # Perform the analysis
    results = analyze_logs(log_file)
    
    if results:
        print_analysis_results(results)
    else:
        print("❌ Analysis failed. Please check the log file and try again.")


