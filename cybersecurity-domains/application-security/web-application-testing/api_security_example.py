#!/usr/bin/env python3
"""
API Security Assessment Tool - Example Usage

This script demonstrates how to use the API Security Assessment tool
programmatically for different testing scenarios.

Author: Omar Santos
Repository: https://github.com/The-Art-of-Hacking/h4cker
"""

from api_security_assessment import APISecurityAssessment

def example_basic_assessment():
    """Example: Basic API security assessment"""
    print("=== Basic API Security Assessment ===")
    
    # Configure target API
    api_url = "https://jsonplaceholder.typicode.com"
    
    # Create assessor instance
    assessor = APISecurityAssessment(api_url)
    
    # Define endpoints to test
    endpoints = ["/posts", "/users", "/comments"]
    
    # Run full assessment
    assessor.run_full_assessment(endpoints)

def example_authenticated_assessment():
    """Example: Assessment with authentication token"""
    print("\n=== Authenticated API Assessment ===")
    
    # Configure target API with authentication
    api_url = "https://api.example.com"
    auth_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."  # Example JWT
    
    # Create assessor with authentication
    assessor = APISecurityAssessment(api_url, auth_token)
    
    # Test specific endpoints
    endpoints = ["/api/v1/users", "/api/v1/orders", "/api/v1/admin"]
    
    # Run assessment
    assessor.run_full_assessment(endpoints)

def example_targeted_testing():
    """Example: Targeted security testing"""
    print("\n=== Targeted Security Testing ===")
    
    api_url = "https://api.vulnerable-app.com"
    assessor = APISecurityAssessment(api_url)
    
    # Test specific security domains
    print("Testing TLS Security...")
    assessor.test_tls_security()
    
    print("Testing for SQL Injection...")
    assessor.test_input_validation(["/search", "/api/query"])
    
    print("Testing for SSRF...")
    assessor.test_ssrf(["/api/fetch", "/webhook"])
    
    print("Testing Management Endpoints...")
    assessor.test_management_endpoints()
    
    # Generate report
    assessor.generate_report()

def example_custom_payloads():
    """Example: Custom security testing with specific focus"""
    print("\n=== Custom Security Testing ===")
    
    api_url = "https://api.myapp.com"
    auth_token = "Bearer your-token-here"
    
    assessor = APISecurityAssessment(api_url, auth_token)
    
    # Test high-risk endpoints
    high_risk_endpoints = [
        "/api/admin/users",
        "/api/payments/process", 
        "/api/data/export",
        "/api/system/config"
    ]
    
    print("Testing Authorization Controls...")
    assessor.test_authorization(high_risk_endpoints)
    
    print("Testing Input Validation...")
    assessor.test_input_validation(high_risk_endpoints)
    
    print("Testing Rate Limiting...")
    for endpoint in high_risk_endpoints:
        assessor.test_rate_limiting(endpoint, limit=50)
    
    # Generate final report
    assessor.generate_report()

def example_batch_testing():
    """Example: Batch testing multiple APIs"""
    print("\n=== Batch API Testing ===")
    
    # List of APIs to test
    apis_to_test = [
        {"url": "https://api1.example.com", "token": None},
        {"url": "https://api2.example.com", "token": "token123"},
        {"url": "https://api3.example.com", "token": "Bearer xyz789"}
    ]
    
    for i, api_config in enumerate(apis_to_test, 1):
        print(f"\n--- Testing API {i}: {api_config['url']} ---")
        
        assessor = APISecurityAssessment(
            api_config['url'], 
            api_config['token']
        )
        
        # Run quick assessment
        common_endpoints = ["/api/users", "/api/data", "/health"]
        assessor.run_full_assessment(common_endpoints)

def example_ci_cd_integration():
    """Example: CI/CD pipeline integration"""
    print("\n=== CI/CD Integration Example ===")
    
    import os
    import sys
    
    # Get configuration from environment variables
    api_url = os.getenv('API_URL', 'https://api.staging.example.com')
    auth_token = os.getenv('API_TOKEN')
    
    if not api_url:
        print("ERROR: API_URL environment variable not set")
        sys.exit(1)
    
    print(f"Testing API: {api_url}")
    
    assessor = APISecurityAssessment(api_url, auth_token)
    
    # Run assessment
    endpoints = ["/api/v1/health", "/api/v1/users", "/api/v1/data"]
    assessor.run_full_assessment(endpoints)
    
    # Check for critical findings
    critical_findings = [f for f in assessor.findings if f.severity == "CRITICAL"]
    high_findings = [f for f in assessor.findings if f.severity == "HIGH"]
    
    if critical_findings:
        print(f"\n❌ CRITICAL SECURITY ISSUES FOUND: {len(critical_findings)}")
        for finding in critical_findings:
            print(f"  - {finding.title}")
        sys.exit(1)  # Fail the build
    
    elif high_findings:
        print(f"\n⚠️  HIGH SEVERITY ISSUES FOUND: {len(high_findings)}")
        for finding in high_findings:
            print(f"  - {finding.title}")
        # Continue but warn
    
    else:
        print("\n✅ No critical or high severity issues found")

if __name__ == "__main__":
    """Run example assessments"""
    
    print("API Security Assessment Tool - Examples")
    print("=" * 50)
    
    # Uncomment the examples you want to run:
    
    # Basic assessment (safe to run against public APIs)
    example_basic_assessment()
    
    # Authenticated assessment (requires valid API and token)
    # example_authenticated_assessment()
    
    # Targeted testing (requires test API)
    # example_targeted_testing()
    
    # Custom payloads (requires test API)
    # example_custom_payloads()
    
    # Batch testing (requires multiple test APIs)
    # example_batch_testing()
    
    # CI/CD integration (requires environment variables)
    # example_ci_cd_integration()
    
    print("\n" + "=" * 50)
    print("Examples completed!")
    print("\nTo run other examples, uncomment them in the main section.")
    print("Remember to only test APIs you own or have permission to test!")
