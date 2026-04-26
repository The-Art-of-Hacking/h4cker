# What is Nikto?

Nikto is an open-source, command-line vulnerability scanner that focuses on web servers and web applications. It identifies potentially dangerous files, outdated server components, and other security issues. While Nikto is not an exploit tool, it flags issues that may be leveraged by attackers if left unchecked. It’s often used by penetration testers, security researchers, and system administrators to quickly assess the security posture of web servers.

🔥 You can complete several labs (including one about Nikto) in O'Reilly. They are listed at: https://hackingscenarios.com

## Basic Usage

The simplest way to run Nikto:
```bash
nikto -h http://example.com
```
Here, `-h` specifies the target host. Nikto will enumerate known checks against `http://example.com`.

### Targeting HTTPS

To scan an HTTPS site:
```bash
nikto -h https://example.com
```
Nikto will automatically handle SSL/TLS.

### Specifying Ports and IPs

If your web server runs on a non-standard port:
```bash
nikto -h 10.6.6.6 -p 8080
```
This scans the IP `10.6.6.6` on port `8080`.

### Multiple Targets

You can supply a list of hosts in a text file:
```
http://10.6.6.23
https://web.test.local
http://www.example.com
```
Run:
```bash
nikto -h targets.txt
```
Nikto will scan each target sequentially.

---

## Common Command-Line Options

- **`-h <host>`**: Specifies the target host (or file containing hosts).
- **`-p <port>`**: Specifies port other than 80/443.
- **`-ssl`**: Forces SSL mode if Nikto doesn’t detect it automatically.
- **`-Tuning <options>`**: Controls what type of tests to run. Tuning options are digits representing categories like file uploads, injections, etc. For example:  
  - `-Tuning 1` might check for interesting file extensions.  
  - `-Tuning 1 2 3` would run tests of categories 1,2, and 3.
- **`-Plugins <plugin-list>`**: Run specific plugins or exclude plugins.
- **`-timeout <seconds>`**: Set a timeout per request.
- **`-output <file>`**: Save the results to a file. You can also specify formats with `-Format`.
- **`-Format <type>`**: Change the output format (html, xml, csv).

### Example with Tuning and Output

```bash
nikto -h http://10.6.6.6 -Tuning 123 -output scan_results.html -Format html
```
This runs tests of categories 1, 2, and 3, and outputs the results to an HTML file named `scan_results.html`.

---

## Running Nikto Against a Sample Target

Let’s say we have a web server at `http://10.6.6.6`:

1. **Basic Scan:**
   ```bash
   nikto -h http://10.6.6.6
   ```
   This will:
   - Enumerate known vulnerabilities and misconfigurations.
   - Check for default files, like `/phpmyadmin/` directories, `/test/`, `/admin/` pages.
   - Identify the server banner, giving clues about the server software and version.
   
   The output might look like:
   ```
   - Nikto v2.1.6
   ---------------------------------------------------------------------------
   + Target IP:          10.6.6.6
   + Target Hostname:    10.6.6.6
   + Target Port:        80
   + Start Time:         2025-12-10 10:00:00 (GMT)
   ---------------------------------------------------------------------------
   + Server: Apache/2.4.41 (Ubuntu)
   + The anti-clickjacking X-Frame-Options header is not present.
   + Allowed HTTP Methods: GET, HEAD, POST, OPTIONS
   + /server-status: Server status page is publicly accessible.
   + /phpmyadmin/: phpMyAdmin directory found. Possible configuration issue.
   + ...
   ```
   Nikto will list identified issues as well as informational messages.

2. **SSL Scans:**
   If the site is `https://10.6.6.6`, run:
   ```bash
   nikto -h https://10.6.6.6
   ```
   Nikto will attempt SSL tests and report SSL-related issues (like weak ciphers or protocols if found).

3. **Specific Tuning:**
   If you want only injection-related tests (just as an example), you need to know which tuning numbers correspond to injection. Usually, `-list-plugins` or referencing Nikto’s documentation helps. As an example:
   ```bash
   nikto -h http://10.6.6.6 -Tuning x
   ```
   Replace `x` with the correct number(s) for injection tests.

4. **More Controlled Testing:**
   To avoid being too noisy, you might exclude certain tests:
   ```bash
   nikto -h http://10.6.6.6 -exclude /server-status
   ```
   This will skip checking `/server-status`.

---

## Interpreting Results

Nikto’s output includes:

- **Server Headers and Banners:**  
  This shows what server software is running and can hint if it’s outdated or misconfigured.

- **Identified Directories and Files:**  
  Paths like `/phpmyadmin/` or `/test/` might be sensitive. Finding these can guide you to configuration changes (like removing or securing these directories).

- **Insecure HTTP Methods:**  
  If `PUT`, `DELETE`, or `TRACE` methods are enabled, Nikto will flag them, as these can be abused.

- **Missing Security Headers:**  
  If headers like `X-Frame-Options`, `X-Content-Type-Options`, or `Content-Security-Policy` are missing, Nikto will note it. While not always critical vulnerabilities, adding these headers helps harden the server.

- **Outdated Software:**  
  If it detects that the server or a known application is out of date, it will alert you to potential vulnerabilities in older versions.

**After a Nikto scan**, you should review the findings and prioritize them:
- High-priority: Default admin panels accessible, outdated software with known CVEs, risky HTTP methods.
- Medium-priority: Exposed server status pages or directory listings.
- Low-priority: Missing headers or other best-practice improvements.

---

## Reporting

Nikto supports output in different formats. For example, to generate HTML output:

```bash
nikto -h http://10.6.6.6 -Format html -output nikto_report.html
```

This creates a more presentable report which you can share with team members or integrate into documentation. XML or CSV outputs are useful for integrating results into other security tools or dashboards.

---

## Advanced Usage

- **Using Proxies:**
  If you want to pass Nikto’s traffic through a proxy (for logging or anonymization):
  ```bash
  nikto -h http://10.6.6.6 -useproxy http://127.0.0.1:8080
  ```
  This is useful when combining Nikto with tools like Burp Suite for traffic inspection.

- **Verbose and Debug Modes:**
  Add `-verbose` or `-Display V` to see more details about what’s happening:
  ```bash
  nikto -h http://10.6.6.6 -Display V
  ```

- **Plug-in Management:**
  To see what plugins are available:
  ```bash
  nikto -list-plugins
  ```
  Then enable or disable plugins with `-Plugins`.

---

## Limitations and Complementary Tools

- **No Exploitation:**  
  Nikto only identifies potential issues. It does not exploit them. Use other tools (like Metasploit) or manual methods to verify vulnerabilities and impact.
  
- **False Positives and Verification:**  
  Like any scanner, Nikto can produce false positives. Always verify findings manually or with another scanner.

- **Speed and Noise:**  
  Nikto can be noisy and somewhat slow. It’s best for initial reconnaissance. For more stealthy, focused testing, consider other tools or refine your Nikto options.

- **Supplement with Other Tools:**  
  Combine Nikto with tools like `Nmap` (for port scanning and service version detection), `Nuclei` (for specific known-vulnerability checks), and manual inspection. analysis or remediation.
