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

The following are the typical components of a template:

1. `id`: Unique identifier for the template
2. `info`: Metadata about the template
3. `requests`: Defines the HTTP requests to be made
4. `matchers`: Specifies conditions to identify vulnerabilities

### Example: CVE Detection Template

Example template for detecting CVE-2021-44228 (Log4j vulnerability):

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


## Additional Examples of Basic Usage

The simplest command to run Nuclei against a single target is:

```bash
nuclei -target http://10.6.6.6
```

This uses the default directory of templates (`~/.nuclei-templates/`). To specify a particular template or directory, use `-t`:

```bash
nuclei -target http://10.6.6.6 -t nuclei-templates/cves/
```

Nuclei can also take a list of targets (e.g., multiple IPs, domains) from a file:

```bash
nuclei -l targets.txt -t nuclei-templates/misconfiguration/
```

---

## Preparing for the Example Scan

### Our Scenario

- **Target:** `10.6.6.6`
- **Possible Services:** Let’s assume this IP hosts a web service on port 80/443.  
- **Goals:**
  1. Enumerate potential vulnerabilities using a broad template set.
  2. Check for known CVEs in popular web frameworks.
  3. Identify misconfigurations or sensitive endpoints.

### Adjusting the Command

For internal scans (like scanning `http://10.6.6.6`), you might want to:
- Specify the template directory.
- Focus on particular template categories.
- Adjust rate limits to avoid overwhelming the target.

#### Example Commands:

1. **Run all default templates against the target:**
   ```bash
   nuclei -u http://10.6.6.6 -t ~/.nuclei-templates/
   ```
   
   This can be quite noisy; it tries all templates. It’s often better to narrow down the scope.

2. **Targeting Specific Categories:**
   For instance, just run CVE-related templates:
   ```bash
   nuclei -u http://10.6.6.6 -t ~/.nuclei-templates/cves/
   ```
   
   This will check common CVE patterns. If the web service is a known framework (WordPress, Joomla, etc.), these templates might find known issues.

3. **Running a Specific Template:**
   Suppose you suspect the server might be running phpMyAdmin and you want to detect any phpMyAdmin login panel exposures. Find the phpMyAdmin templates (for example `exposed-panels/phpmyadmin-login.yaml`) and run:
   ```bash
   nuclei -u http://10.6.6.6 -t ~/.nuclei-templates/exposed-panels/phpmyadmin-login.yaml
   ```

4. **Setting Rate Limits and Concurrency:**
   If you’re scanning a network service that might be sensitive, slow down the requests:
   ```bash
   nuclei -u http://10.6.6.6 -t ~/.nuclei-templates/ -rl 50 -c 10
   ```
   `-rl 50` limits to 50 requests per second and `-c 10` sets concurrency to 10 templates at a time.

---

## Interpreting Results

The output of Nuclei prints findings to the terminal. A typical finding might look like:

```
[critical] [cves/2021/CVE-2021-XXXXX.yaml] http://10.6.6.6/vulnerable-endpoint
```

- **Severity Tag:** `[critical]` indicates the severity level from the template.
- **Template Info:** `cves/2021/CVE-2021-XXXXX.yaml` indicates which template matched.
- **Matched URL:** `http://10.6.6.6/vulnerable-endpoint` is the discovered vulnerable endpoint.

You can also output results to a file:

```bash
nuclei -u http://10.6.6.6 -t ~/.nuclei-templates/ -o results.txt
```

Nuclei can also output in JSON for easier parsing:

```bash
nuclei -u http://10.6.6.6 -t ~/.nuclei-templates/ -json -o results.json
```

---

## Running Against Multiple Targets in the 10.6.6.0/24 Network

If you have a list of hosts or endpoints within the network, say `targets.txt`:

```
http://10.6.6.6
http://10.6.6.7
http://10.6.6.8
```

You can run:

```bash
nuclei -l targets.txt -t ~/.nuclei-templates/ -o network_results.txt
```

This will scan each listed host against all templates. To target only a certain set, like misconfiguration checks:

```bash
nuclei -l targets.txt -t ~/.nuclei-templates/misconfiguration/ -o misconfig_results.txt
```



## Advanced Usage: Workflows and Tagging

Nuclei supports:
- **Workflows:** Chain multiple templates so one finding triggers another template.
- **Tagging:** Run templates by tags, like `-tags exposure` to run all templates tagged as `exposure`.

For example, if you want to run only templates that are labeled with `exposure` tag:

```bash
nuclei -u http://10.6.6.6 -tags exposure
```

If you have a workflow file (a collection of templates in a certain order), you can specify it:

```bash
nuclei -u http://10.6.6.6 -w ~/my-workflows/exposure-workflow.yaml
```

---

## Tuning and Optimization

- **Exclude Templates:** Use `-exclude` flag to exclude certain templates or directories that produce false positives or are irrelevant.
- **Stop at First Match:** If you just want to know if there’s any vulnerability at all, you can optimize by stopping after first match with certain parameters.
- **Integration with Other Tools:** Combine Nuclei with subdomain enumeration (e.g., `subfinder`), and pipe results directly. For example:
  ```bash
  echo http://10.6.6.6 | nuclei -t ~/.nuclei-templates/
  ```

---

## Practical Example Recap

Let’s finalize with a practical scenario using the fictitious target:

1. **Initial Broad Scan (All Templates):**
   ```bash
   nuclei -u http://10.6.6.6 -t ~/.nuclei-templates/ -o broad_scan.txt
   ```
   Wait for results. Check `broad_scan.txt` for interesting findings.

2. **Focused CVE Scan:**
   ```bash
   nuclei -u http://10.6.6.6 -t ~/.nuclei-templates/cves/ -o cves_findings.txt
   ```

3. **Misconfiguration Checks:**
   ```bash
   nuclei -u http://10.6.6.6 -t ~/.nuclei-templates/misconfiguration/ -o misconfig_findings.txt
   ```

4. **Custom Endpoint Check:**
   ```bash
   nuclei -u http://10.6.6.6 -t internal-status.yaml -o custom_check.txt
   ```

5. **JSON Output for Tool Integration:**
   ```bash
   nuclei -u http://10.6.6.6 -t ~/.nuclei-templates/ -json -o results.json
   ```
   Then parse `results.json` with a script.





