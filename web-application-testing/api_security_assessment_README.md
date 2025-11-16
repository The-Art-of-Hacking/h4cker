# API Security Assessment Tool

A comprehensive automated security testing tool for REST APIs, covering 9 critical security domains.

## Features

✅ **Transport & TLS Security** - HTTPS enforcement, certificate validation, HSTS headers  
✅ **Authentication Testing** - JWT validation, token lifetime, algorithm security  
✅ **Authorization Testing** - IDOR prevention, privilege escalation, mass assignment  
✅ **Input Validation** - SQL injection, NoSQL injection, command injection  
✅ **SSRF Protection** - URL validation, private IP blocking, cloud metadata protection  
✅ **Rate Limiting** - DoS protection, request throttling  
✅ **Information Disclosure** - Error handling, header exposure, verbose messages  
✅ **Management Endpoints** - Admin interface exposure, debug endpoints  
✅ **CORS Configuration** - Cross-Origin Resource Sharing security  
✅ **Automated Reporting** - JSON export, severity classification, remediation guidance

## Installation

```bash
# Install dependencies
pip install requests pyjwt

# Make script executable (optional)
chmod +x api_security_assessment.py
```

## Quick Start

### Basic Usage

```bash
# Test an API
python api_security_assessment.py --url https://api.example.com

# Test with authentication token
python api_security_assessment.py --url https://api.example.com --token "Bearer your-token-here"

# Test specific endpoints
python api_security_assessment.py \
  --url https://api.example.com \
  --endpoints /api/users,/api/data,/api/search
```

### Advanced Usage

```bash
# Test with custom thread count
python api_security_assessment.py \
  --url https://api.example.com \
  --token "your-jwt-token" \
  --endpoints /api/v1/users,/api/v1/products \
  --threads 20

# Output results in JSON format
python api_security_assessment.py \
  --url https://api.example.com \
  --output json
```

### Programmatic Usage

```python
from api_security_assessment import APISecurityAssessment

# Configure your API
API_URL = "https://your-api.com"
AUTH_TOKEN = "your-jwt-token"  # Optional

# Define endpoints to test
TEST_ENDPOINTS = [
    "/api/v1/users",
    "/api/v1/products", 
    "/api/v1/orders"
]

# Run full assessment
assessor = APISecurityAssessment(API_URL, AUTH_TOKEN)
assessor.run_full_assessment(TEST_ENDPOINTS)
```

### Custom Testing

```python
# Test specific security domains
assessor = APISecurityAssessment(API_URL, AUTH_TOKEN)

# Test only TLS configuration
assessor.test_tls_security()

# Test only authentication
assessor.test_authentication()

# Test authorization on specific endpoints
assessor.test_authorization(["/api/admin", "/api/settings"])

# Test for SQL injection
assessor.test_input_validation(["/api/search"])

# Test for SSRF
assessor.test_ssrf(["/api/webhook"])

# Test rate limiting
assessor.test_rate_limiting("/api/data")

# Test information disclosure
assessor.test_information_disclosure()

# Test management endpoints
assessor.test_management_endpoints()

# Test CORS configuration
assessor.test_cors_configuration()

# Generate report
assessor.generate_report()
```

## Example Output

```
============================================================
API Security Assessment: https://api.example.com
============================================================

=== Testing TLS Security ===
[MEDIUM] Missing HSTS Header

=== Testing Authentication ===
  Token algorithm: RS256
  Token lifetime: 2.0 hours
[MEDIUM] Long JWT Lifetime

=== Testing Authorization ===
  /api/users: Protected (401)
  /api/data: Protected (401)

=== Testing Input Validation ===
[CRITICAL] SQL Injection in /api/search

=== Testing SSRF Protection ===

=== Testing Rate Limiting ===
  Sending 120 requests to test rate limiting...
  Rate limiting detected: 100 successful, 20 rate-limited

=== Testing Information Disclosure ===
[LOW] Header Exposure: Server

=== Testing Management Endpoints ===
[HIGH] Exposed Management Endpoint: /swagger

=== Testing CORS Configuration ===
[MEDIUM] Permissive CORS Policy

============================================================
ASSESSMENT SUMMARY
============================================================

Total Findings: 5
  🔴 CRITICAL: 1
  🟠 HIGH:     1
  🟡 MEDIUM:   3
  🟢 LOW:      1

============================================================
DETAILED FINDINGS
============================================================

1. [CRITICAL] SQL Injection in /api/search
   Category: Input Validation
   Description: Endpoint vulnerable to SQL injection
   Evidence: Payload: ' OR '1'='1, Response contains SQL error
   Remediation: Use parameterized queries and prepared statements

2. [HIGH] Exposed Management Endpoint: /swagger
   Category: Management Endpoints
   Description: Management or admin endpoint accessible without restrictions
   Evidence: Status: 200, Size: 15234 bytes
   Remediation: Restrict access to management endpoints via network controls

...

Report saved to: api_security_assessment_20251116_143022.json
```

## Security Domains Tested

### 1. Transport & TLS Security

- HTTPS enforcement
- HTTP to HTTPS redirect
- HSTS header presence
- TLS version and cipher strength
- Certificate validation

### 2. Authentication

- JWT algorithm validation
- Token signature strength (RS256/ES256 vs HS256/none)
- Token lifetime validation
- Token expiration handling
- Claim validation (iss, aud, exp, nbf, iat)

### 3. Authorization

- Unauthenticated access attempts
- IDOR (Insecure Direct Object Reference)
- Privilege escalation testing
- Mass assignment vulnerabilities
- Resource-level access control

### 4. Input Validation

- SQL injection testing
- NoSQL injection testing
- Command injection testing
- LDAP injection testing
- Schema validation

### 5. SSRF Prevention

- Internal network access (localhost, 127.0.0.1, private IPs)
- Cloud metadata endpoints (AWS, GCP, Azure)
- File protocol access (file://)
- Protocol validation (gopher://, dict://, ftp://)
- DNS rebinding protection

### 6. Rate Limiting & DoS

- Request rate limits per IP
- Request rate limits per user
- Burst protection
- Request size limits
- Timeout enforcement

### 7. Information Disclosure

- Verbose error messages
- Stack traces in responses
- Server header exposure
- Framework version disclosure
- Debug information leakage

### 8. Management Endpoints

- Admin panel exposure
- Debug endpoints
- Health check endpoints
- Metrics endpoints
- API documentation exposure
- Database admin tools

### 9. CORS Configuration

- Wildcard origin policies
- Credential handling
- Origin reflection vulnerabilities
- Method restrictions
- Header restrictions

## Command Line Options

```
usage: api_security_assessment.py [-h] --url URL [--token TOKEN] 
                                  [--endpoints ENDPOINTS] [--output {json,text}]
                                  [--threads THREADS]

Comprehensive API Security Assessment Tool

options:
  -h, --help            show this help message and exit
  --url URL             Base URL of the API to assess (e.g., https://api.example.com)
  --token TOKEN         Authentication token (JWT or Bearer token)
  --endpoints ENDPOINTS Comma-separated list of endpoints to test (e.g., /api/users,/api/data)
  --output {json,text}  Output format (json, text). Default: text
  --threads THREADS     Number of threads for concurrent testing (default: 10)
```

## Security Considerations

### Responsible Testing

- Only test APIs you own or have explicit permission to test
- Be mindful of rate limiting and server load
- Use test environments when possible
- Follow responsible disclosure for any vulnerabilities found

### Limitations

- This tool performs automated testing and may not catch all vulnerabilities
- Manual security testing and code review are still recommended
- Some tests may produce false positives that require manual verification
- Business logic flaws require manual analysis

### Best Practices

1. **Regular Testing**: Run assessments regularly as part of your CI/CD pipeline
2. **Comprehensive Coverage**: Test all API endpoints, not just public ones
3. **Environment Isolation**: Use dedicated test environments
4. **Remediation Tracking**: Track and verify fixes for identified issues
5. **Documentation**: Maintain security testing documentation

## Integration Examples

### CI/CD Pipeline Integration

```yaml
# GitHub Actions example
name: API Security Assessment
on: [push, pull_request]

jobs:
  security-test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Setup Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.9'
    - name: Install dependencies
      run: |
        pip install requests pyjwt
    - name: Run API Security Assessment
      run: |
        python api_security_assessment.py \
          --url ${{ secrets.API_URL }} \
          --token ${{ secrets.API_TOKEN }} \
          --output json
```

### Docker Integration

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY api_security_assessment.py .
RUN pip install requests pyjwt

ENTRYPOINT ["python", "api_security_assessment.py"]
```

```bash
# Build and run
docker build -t api-security-tool .
docker run api-security-tool --url https://api.example.com
```

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:

- Additional security test cases
- New vulnerability detection methods
- Performance improvements
- Documentation enhancements
- Bug fixes

## License

This tool is part of the [h4cker repository](https://github.com/The-Art-of-Hacking/h4cker) and is licensed under the MIT License.

## Author

Created by [Omar Santos](https://omarsantos.io) as part of the h4cker cybersecurity learning resources.

## Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems. The authors are not responsible for any misuse of this tool.
