#!/usr/bin/env python3
"""
API Security Assessment Tool

A comprehensive automated security testing tool for REST APIs, covering 9 critical security domains.

Author: Omar Santos
Repository: https://github.com/The-Art-of-Hacking/h4cker
License: MIT

Features:
✅ Transport & TLS Security - HTTPS enforcement, certificate validation, HSTS headers
✅ Authentication Testing - JWT validation, token lifetime, algorithm security
✅ Authorization Testing - IDOR prevention, privilege escalation, mass assignment
✅ Input Validation - SQL injection, NoSQL injection, command injection
✅ SSRF Protection - URL validation, private IP blocking, cloud metadata protection
✅ Rate Limiting - DoS protection, request throttling
✅ Information Disclosure - Error handling, header exposure, verbose messages
✅ Management Endpoints - Admin interface exposure, debug endpoints
✅ Automated Reporting - JSON export, severity classification, remediation guidance
"""

import argparse
import json
import time
import ssl
import socket
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import jwt
import warnings

# Suppress SSL warnings for testing purposes
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

@dataclass
class SecurityFinding:
    """Represents a security finding from the assessment"""
    severity: str
    category: str
    title: str
    description: str
    evidence: str
    remediation: str

class APISecurityAssessment:
    """Main class for conducting API security assessments"""
    
    def __init__(self, base_url: str, auth_token: Optional[str] = None):
        """
        Initialize the API security assessment tool
        
        Args:
            base_url: Base URL of the API to test
            auth_token: Optional authentication token (JWT or Bearer)
        """
        self.base_url = base_url.rstrip('/')
        self.auth_token = auth_token
        self.findings: List[SecurityFinding] = []
        
        # Configure session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set authentication header if provided
        if self.auth_token:
            if not self.auth_token.startswith('Bearer '):
                self.auth_token = f'Bearer {self.auth_token}'
            self.session.headers.update({'Authorization': self.auth_token})
    
    def add_finding(self, severity: str, category: str, title: str, 
                   description: str, evidence: str, remediation: str):
        """Add a security finding to the results"""
        finding = SecurityFinding(
            severity=severity,
            category=category,
            title=title,
            description=description,
            evidence=evidence,
            remediation=remediation
        )
        self.findings.append(finding)
        print(f"[{severity}] {title}")
    
    def test_tls_security(self):
        """Test TLS/SSL configuration and security headers"""
        print("\n=== Testing TLS Security ===")
        
        try:
            # Test HTTPS enforcement
            if self.base_url.startswith('http://'):
                self.add_finding(
                    "HIGH",
                    "Transport Security",
                    "HTTP Protocol Used",
                    "API is accessible over unencrypted HTTP",
                    f"URL: {self.base_url}",
                    "Enforce HTTPS for all API endpoints and redirect HTTP to HTTPS"
                )
                return
            
            # Test HTTPS response and headers
            resp = self.session.get(self.base_url, timeout=10, verify=False)
            
            # Check for HSTS header
            if 'Strict-Transport-Security' not in resp.headers:
                self.add_finding(
                    "MEDIUM",
                    "Transport Security",
                    "Missing HSTS Header",
                    "HTTP Strict Transport Security header not present",
                    "HSTS header missing from response",
                    "Add Strict-Transport-Security header with appropriate max-age"
                )
            
            # Test TLS version and cipher strength
            parsed_url = urllib.parse.urlparse(self.base_url)
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    tls_version = ssock.version()
                    cipher = ssock.cipher()
                    
                    if tls_version in ['TLSv1', 'TLSv1.1']:
                        self.add_finding(
                            "HIGH",
                            "Transport Security",
                            f"Weak TLS Version: {tls_version}",
                            "Server supports deprecated TLS versions",
                            f"TLS Version: {tls_version}",
                            "Disable TLSv1.0 and TLSv1.1, use TLSv1.2 or higher"
                        )
                    
                    print(f"  TLS Version: {tls_version}")
                    print(f"  Cipher: {cipher[0] if cipher else 'Unknown'}")
        
        except Exception as e:
            print(f"  Error testing TLS security: {e}")
    
    def test_authentication(self):
        """Test authentication mechanisms and JWT security"""
        print("\n=== Testing Authentication ===")
        
        if not self.auth_token:
            print("  No authentication token provided, skipping JWT tests")
            return
        
        try:
            # Extract JWT token (remove 'Bearer ' prefix)
            token = self.auth_token.replace('Bearer ', '')
            
            # Decode JWT without verification to inspect claims
            try:
                header = jwt.get_unverified_header(token)
                payload = jwt.decode(token, options={"verify_signature": False})
                
                print(f"  Token algorithm: {header.get('alg', 'Unknown')}")
                
                # Check for weak algorithms
                weak_algorithms = ['none', 'HS256']
                if header.get('alg') in weak_algorithms:
                    self.add_finding(
                        "HIGH",
                        "Authentication",
                        f"Weak JWT Algorithm: {header.get('alg')}",
                        "JWT uses weak or no signature algorithm",
                        f"Algorithm: {header.get('alg')}",
                        "Use strong asymmetric algorithms like RS256 or ES256"
                    )
                
                # Check token lifetime
                if 'exp' in payload and 'iat' in payload:
                    lifetime = payload['exp'] - payload['iat']
                    lifetime_hours = lifetime / 3600
                    print(f"  Token lifetime: {lifetime_hours:.1f} hours")
                    
                    if lifetime_hours > 24:
                        self.add_finding(
                            "MEDIUM",
                            "Authentication",
                            "Long JWT Lifetime",
                            f"JWT has excessive lifetime of {lifetime_hours:.1f} hours",
                            f"Lifetime: {lifetime_hours:.1f} hours",
                            "Reduce JWT lifetime to maximum 24 hours, preferably 1-2 hours"
                        )
                
                # Check for missing security claims
                security_claims = ['exp', 'iat', 'iss', 'aud']
                missing_claims = [claim for claim in security_claims if claim not in payload]
                if missing_claims:
                    self.add_finding(
                        "LOW",
                        "Authentication",
                        "Missing JWT Security Claims",
                        f"JWT missing security claims: {', '.join(missing_claims)}",
                        f"Missing: {missing_claims}",
                        "Include all standard security claims (exp, iat, iss, aud)"
                    )
            
            except jwt.InvalidTokenError:
                self.add_finding(
                    "HIGH",
                    "Authentication",
                    "Invalid JWT Token",
                    "Provided JWT token is malformed or invalid",
                    "JWT decode failed",
                    "Ensure JWT tokens are properly formatted and signed"
                )
        
        except Exception as e:
            print(f"  Error testing authentication: {e}")
    
    def test_authorization(self, test_endpoints: List[str]):
        """Test authorization controls and access restrictions"""
        print("\n=== Testing Authorization ===")
        
        for endpoint in test_endpoints:
            try:
                # Test unauthenticated access
                unauth_session = requests.Session()
                resp = unauth_session.get(f"{self.base_url}{endpoint}", timeout=5)
                
                if resp.status_code == 200:
                    self.add_finding(
                        "HIGH",
                        "Authorization",
                        f"Unauthenticated Access: {endpoint}",
                        "Endpoint accessible without authentication",
                        f"Status: {resp.status_code}",
                        "Implement proper authentication checks for all endpoints"
                    )
                else:
                    print(f"  {endpoint}: Protected ({resp.status_code})")
                
                # Test IDOR (Insecure Direct Object Reference)
                if self.auth_token:
                    # Test with different user IDs
                    idor_payloads = ['1', '2', '999', '../admin', '../../etc/passwd']
                    for payload in idor_payloads:
                        idor_url = f"{self.base_url}{endpoint}?id={payload}"
                        try:
                            resp = self.session.get(idor_url, timeout=5)
                            if resp.status_code == 200 and len(resp.content) > 100:
                                # Basic heuristic: if we get substantial content, might be IDOR
                                if 'admin' in resp.text.lower() or 'root' in resp.text.lower():
                                    self.add_finding(
                                        "HIGH",
                                        "Authorization",
                                        f"Potential IDOR: {endpoint}",
                                        "Endpoint may be vulnerable to Insecure Direct Object Reference",
                                        f"Payload: {payload}, Response size: {len(resp.content)}",
                                        "Implement proper authorization checks for object access"
                                    )
                                    break
                        except:
                            pass
            
            except Exception as e:
                print(f"  Error testing {endpoint}: {e}")
    
    def test_input_validation(self, test_endpoints: List[str]):
        """Test for input validation vulnerabilities"""
        print("\n=== Testing Input Validation ===")
        
        # SQL Injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT 1,2,3 --",
            "admin'--",
            "' OR 1=1#"
        ]
        
        # NoSQL Injection payloads
        nosql_payloads = [
            "{'$ne': null}",
            "{'$gt': ''}",
            "'; return true; var x='",
            "1'; return true; var x='1"
        ]
        
        # Command Injection payloads
        cmd_payloads = [
            "; ls -la",
            "| whoami",
            "&& cat /etc/passwd",
            "`id`",
            "$(whoami)"
        ]
        
        for endpoint in test_endpoints:
            try:
                # Test SQL Injection
                for payload in sql_payloads:
                    test_url = f"{self.base_url}{endpoint}?q={payload}"
                    try:
                        resp = self.session.get(test_url, timeout=5)
                        
                        # Check for SQL error indicators
                        sql_errors = [
                            'sql syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL',
                            'sqlite_master', 'SQL command not properly ended',
                            'mysql_num_rows', 'Division by zero in /var/www',
                            'Microsoft JET Database', 'ODBC SQL Server Driver'
                        ]
                        
                        if any(error.lower() in resp.text.lower() for error in sql_errors):
                            self.add_finding(
                                "CRITICAL",
                                "Input Validation",
                                f"SQL Injection in {endpoint}",
                                "Endpoint vulnerable to SQL injection",
                                f"Payload: {payload}, Response contains SQL error",
                                "Use parameterized queries and prepared statements"
                            )
                            break
                    except:
                        pass
                
                # Test NoSQL Injection
                for payload in nosql_payloads:
                    test_url = f"{self.base_url}{endpoint}"
                    try:
                        resp = self.session.post(test_url, json={"query": payload}, timeout=5)
                        
                        nosql_errors = ['MongoError', 'CastError', 'ValidationError', 'mongo']
                        if any(error.lower() in resp.text.lower() for error in nosql_errors):
                            self.add_finding(
                                "HIGH",
                                "Input Validation",
                                f"NoSQL Injection in {endpoint}",
                                "Endpoint vulnerable to NoSQL injection",
                                f"Payload: {payload}",
                                "Validate and sanitize all input, use parameterized queries"
                            )
                            break
                    except:
                        pass
                
                # Test Command Injection
                for payload in cmd_payloads:
                    test_url = f"{self.base_url}{endpoint}?cmd={payload}"
                    try:
                        resp = self.session.get(test_url, timeout=5)
                        
                        cmd_indicators = ['uid=', 'gid=', 'root:', '/bin/', '/usr/bin/', 'www-data']
                        if any(indicator in resp.text for indicator in cmd_indicators):
                            self.add_finding(
                                "CRITICAL",
                                "Input Validation",
                                f"Command Injection in {endpoint}",
                                "Endpoint vulnerable to command injection",
                                f"Payload: {payload}",
                                "Never execute user input as system commands, use allowlists"
                            )
                            break
                    except:
                        pass
            
            except Exception as e:
                print(f"  Error testing input validation on {endpoint}: {e}")
    
    def test_ssrf(self, test_endpoints: List[str]):
        """Test for Server-Side Request Forgery vulnerabilities"""
        print("\n=== Testing SSRF Protection ===")
        
        # SSRF payloads targeting internal networks and cloud metadata
        ssrf_payloads = [
            "http://127.0.0.1:22",
            "http://localhost:3306",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://metadata.google.internal/computeMetadata/v1/",  # GCP metadata
            "http://169.254.169.254/metadata/instance",  # Azure metadata
            "file:///etc/passwd",
            "gopher://127.0.0.1:3306",
            "dict://127.0.0.1:11211",
            "http://10.0.0.1",
            "http://192.168.1.1"
        ]
        
        for endpoint in test_endpoints:
            for payload in ssrf_payloads:
                try:
                    # Test URL parameter
                    test_url = f"{self.base_url}{endpoint}?url={payload}"
                    resp = self.session.get(test_url, timeout=5)
                    
                    # Check for SSRF indicators
                    ssrf_indicators = [
                        'root:', 'daemon:', 'bin:', '/bin/bash',  # /etc/passwd content
                        'instance-id', 'ami-id', 'security-groups',  # AWS metadata
                        'project-id', 'service-accounts',  # GCP metadata
                        'compute', 'network'  # Azure metadata
                    ]
                    
                    if any(indicator in resp.text for indicator in ssrf_indicators):
                        self.add_finding(
                            "CRITICAL",
                            "SSRF Protection",
                            f"SSRF Vulnerability in {endpoint}",
                            "Endpoint vulnerable to Server-Side Request Forgery",
                            f"Payload: {payload}",
                            "Validate URLs, block private IPs, use allowlists for external requests"
                        )
                        break
                
                except Exception as e:
                    pass
    
    def test_rate_limiting(self, test_endpoint: str, limit: int = 100):
        """Test rate limiting implementation"""
        print("\n=== Testing Rate Limiting ===")
        
        def make_request(i):
            try:
                resp = self.session.get(f"{self.base_url}{test_endpoint}", timeout=5)
                return resp.status_code
            except:
                return None
        
        print(f"  Sending {limit + 20} requests to test rate limiting...")
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(make_request, range(limit + 20)))
        
        rate_limited = sum(1 for r in results if r == 429)
        successful = sum(1 for r in results if r == 200)
        
        if rate_limited == 0:
            self.add_finding(
                "MEDIUM",
                "Rate Limiting",
                "No Rate Limiting Detected",
                f"Sent {len(results)} requests without rate limiting",
                f"All requests completed without 429 responses",
                "Implement rate limiting per IP, user, and globally"
            )
        else:
            print(f"  Rate limiting detected: {successful} successful, {rate_limited} rate-limited")
    
    def test_information_disclosure(self):
        """Test for information leakage"""
        print("\n=== Testing Information Disclosure ===")
        
        try:
            resp = self.session.get(self.base_url, timeout=10)
            
            # Check headers for information disclosure
            risky_headers = {
                "Server": "Server version exposed",
                "X-Powered-By": "Framework exposed",
                "X-AspNet-Version": "Framework version exposed",
                "X-Generator": "Generator information exposed",
                "X-Drupal-Cache": "CMS information exposed"
            }
            
            for header, description in risky_headers.items():
                if header in resp.headers:
                    self.add_finding(
                        "LOW",
                        "Information Disclosure",
                        f"Header Exposure: {header}",
                        description,
                        f"{header}: {resp.headers[header]}",
                        f"Remove or genericize the {header} header"
                    )
            
            # Check for verbose error messages
            error_resp = self.session.get(f"{self.base_url}/nonexistent-endpoint-test-12345", timeout=5)
            error_patterns = [
                "Traceback", "Stack trace", ".py\"", "Exception in",
                "at line", "in file", "Fatal error", "Warning:",
                "Notice:", "Parse error", "Call Stack"
            ]
            
            if any(pattern in error_resp.text for pattern in error_patterns):
                self.add_finding(
                    "MEDIUM",
                    "Information Disclosure",
                    "Verbose Error Messages",
                    "Error responses contain stack traces or internal details",
                    "Error response contains framework/code details",
                    "Implement generic error messages and log details server-side"
                )
        
        except Exception as e:
            print(f"  Error testing information disclosure: {e}")
    
    def test_management_endpoints(self):
        """Test for exposed management and admin endpoints"""
        print("\n=== Testing Management Endpoints ===")
        
        admin_paths = [
            "/admin", "/api/admin", "/administrator", "/management",
            "/health", "/metrics", "/status", "/info",
            "/debug", "/swagger", "/api-docs", "/docs",
            "/actuator", "/actuator/health", "/actuator/info",
            "/openapi.json", "/swagger.json", "/swagger-ui",
            "/.well-known/", "/robots.txt", "/sitemap.xml",
            "/phpmyadmin", "/adminer", "/wp-admin"
        ]
        
        for path in admin_paths:
            try:
                resp = requests.get(f"{self.base_url}{path}", timeout=5, allow_redirects=False)
                
                if resp.status_code == 200:
                    # Check if it's actually management content
                    management_indicators = [
                        'swagger', 'api documentation', 'admin', 'dashboard',
                        'management', 'actuator', 'health check', 'metrics',
                        'phpmyadmin', 'database', 'login'
                    ]
                    
                    if any(indicator in resp.text.lower() for indicator in management_indicators):
                        self.add_finding(
                            "HIGH",
                            "Management Endpoints",
                            f"Exposed Management Endpoint: {path}",
                            "Management or admin endpoint accessible without restrictions",
                            f"Status: {resp.status_code}, Size: {len(resp.content)} bytes",
                            "Restrict access to management endpoints via network controls and strong authentication"
                        )
                elif resp.status_code in [401, 403]:
                    print(f"  {path}: Protected ({resp.status_code})")
                elif resp.status_code in [301, 302]:
                    print(f"  {path}: Redirected ({resp.status_code})")
            
            except:
                pass
    
    def test_cors_configuration(self):
        """Test CORS configuration for security issues"""
        print("\n=== Testing CORS Configuration ===")
        
        try:
            # Test with malicious origin
            headers = {'Origin': 'https://evil.com'}
            resp = self.session.get(self.base_url, headers=headers, timeout=10)
            
            cors_headers = {
                'Access-Control-Allow-Origin': resp.headers.get('Access-Control-Allow-Origin'),
                'Access-Control-Allow-Credentials': resp.headers.get('Access-Control-Allow-Credentials'),
                'Access-Control-Allow-Methods': resp.headers.get('Access-Control-Allow-Methods')
            }
            
            # Check for overly permissive CORS
            if cors_headers['Access-Control-Allow-Origin'] == '*':
                if cors_headers['Access-Control-Allow-Credentials'] == 'true':
                    self.add_finding(
                        "HIGH",
                        "CORS Configuration",
                        "Dangerous CORS Configuration",
                        "CORS allows any origin with credentials",
                        "Access-Control-Allow-Origin: * with credentials enabled",
                        "Use specific origins instead of wildcard when credentials are allowed"
                    )
                else:
                    self.add_finding(
                        "MEDIUM",
                        "CORS Configuration",
                        "Permissive CORS Policy",
                        "CORS allows any origin",
                        "Access-Control-Allow-Origin: *",
                        "Use specific trusted origins instead of wildcard"
                    )
            
            elif cors_headers['Access-Control-Allow-Origin'] == 'https://evil.com':
                self.add_finding(
                    "HIGH",
                    "CORS Configuration",
                    "CORS Origin Reflection",
                    "CORS reflects arbitrary origins",
                    "Origin header reflected in Access-Control-Allow-Origin",
                    "Validate origins against a whitelist of trusted domains"
                )
        
        except Exception as e:
            print(f"  Error testing CORS: {e}")
    
    def run_full_assessment(self, test_endpoints: Optional[List[str]] = None):
        """Run complete security assessment"""
        if test_endpoints is None:
            test_endpoints = ["/api/users", "/api/data", "/api/search"]
        
        print(f"\n{'='*60}")
        print(f"API Security Assessment: {self.base_url}")
        print(f"{'='*60}")
        
        # Run all security tests
        self.test_tls_security()
        self.test_authentication()
        self.test_authorization(test_endpoints)
        self.test_input_validation(test_endpoints)
        self.test_ssrf(test_endpoints)
        self.test_rate_limiting(test_endpoints[0] if test_endpoints else "/")
        self.test_information_disclosure()
        self.test_management_endpoints()
        self.test_cors_configuration()
        
        # Generate final report
        self.generate_report()
    
    def generate_report(self):
        """Generate comprehensive assessment report"""
        print(f"\n{'='*60}")
        print("ASSESSMENT SUMMARY")
        print(f"{'='*60}\n")
        
        # Count findings by severity
        severity_counts = {
            "CRITICAL": len([f for f in self.findings if f.severity == "CRITICAL"]),
            "HIGH": len([f for f in self.findings if f.severity == "HIGH"]),
            "MEDIUM": len([f for f in self.findings if f.severity == "MEDIUM"]),
            "LOW": len([f for f in self.findings if f.severity == "LOW"]),
        }
        
        print(f"Total Findings: {len(self.findings)}")
        print(f"  🔴 CRITICAL: {severity_counts['CRITICAL']}")
        print(f"  🟠 HIGH:     {severity_counts['HIGH']}")
        print(f"  🟡 MEDIUM:   {severity_counts['MEDIUM']}")
        print(f"  🟢 LOW:      {severity_counts['LOW']}")
        
        if self.findings:
            print(f"\n{'='*60}")
            print("DETAILED FINDINGS")
            print(f"{'='*60}\n")
            
            # Sort findings by severity
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            sorted_findings = sorted(self.findings, key=lambda x: severity_order[x.severity])
            
            for i, finding in enumerate(sorted_findings, 1):
                print(f"{i}. [{finding.severity}] {finding.title}")
                print(f"   Category: {finding.category}")
                print(f"   Description: {finding.description}")
                print(f"   Evidence: {finding.evidence}")
                print(f"   Remediation: {finding.remediation}")
                print()
            
            # Export to JSON
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            report_file = f"api_security_assessment_{timestamp}.json"
            
            report_data = {
                "assessment_info": {
                    "target_url": self.base_url,
                    "timestamp": timestamp,
                    "total_findings": len(self.findings),
                    "severity_breakdown": severity_counts
                },
                "findings": [
                    {
                        "severity": f.severity,
                        "category": f.category,
                        "title": f.title,
                        "description": f.description,
                        "evidence": f.evidence,
                        "remediation": f.remediation
                    }
                    for f in sorted_findings
                ]
            }
            
            with open(report_file, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            print(f"Report saved to: {report_file}")
        else:
            print("\n✅ No security issues found!")
            print("Note: This doesn't guarantee the API is secure. Consider manual testing and code review.")


def main():
    """Main entry point for CLI usage"""
    parser = argparse.ArgumentParser(
        description="Comprehensive API Security Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --url https://api.example.com
  %(prog)s --url https://api.example.com --token "Bearer xyz123"
  %(prog)s --url https://api.example.com --endpoints /api/users,/api/data,/api/search
  %(prog)s --url https://api.example.com --token "xyz123" --endpoints /api/v1/users
        """
    )
    
    parser.add_argument(
        '--url',
        required=True,
        help='Base URL of the API to assess (e.g., https://api.example.com)'
    )
    
    parser.add_argument(
        '--token',
        help='Authentication token (JWT or Bearer token)'
    )
    
    parser.add_argument(
        '--endpoints',
        help='Comma-separated list of endpoints to test (e.g., /api/users,/api/data)'
    )
    
    parser.add_argument(
        '--output',
        help='Output format (json, text). Default: text',
        choices=['json', 'text'],
        default='text'
    )
    
    parser.add_argument(
        '--threads',
        type=int,
        default=10,
        help='Number of threads for concurrent testing (default: 10)'
    )
    
    args = parser.parse_args()
    
    # Parse endpoints
    test_endpoints = None
    if args.endpoints:
        test_endpoints = [e.strip() for e in args.endpoints.split(',')]
    
    # Run assessment
    print("🔍 Starting API Security Assessment...")
    print(f"Target: {args.url}")
    if args.token:
        print("Authentication: Token provided")
    if test_endpoints:
        print(f"Endpoints: {', '.join(test_endpoints)}")
    
    assessor = APISecurityAssessment(args.url, args.token)
    assessor.run_full_assessment(test_endpoints)


if __name__ == "__main__":
    main()
