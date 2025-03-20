# Nikto Cheat Sheet

Nikto is an open-source web server vulnerability scanner used to identify potential security issues in web applications and servers. Below is a cheat sheet highlighting its key features and commands.

### 1. **Basic Nikto Commands**

- **Scan a Host**: `nikto -h `  
  Initiates a basic scan against a specified target URL.

- **Scan Specific Ports**: `nikto -h  -p ,`  
  Scans the target on specified ports.

- **Use SSL**: `nikto -h  -ssl`  
  Enables SSL scanning for HTTPS services.

- **Save Output**: `nikto -h  -o `  
  Saves scan results to a specified file.

### 2. **Advanced Options**

- **Specify Host Header**: `nikto -h  -host `  
  Sets the Host header for the request.

- **Disable 404 Checks**: `nikto -h  -no404`  
  Skips HTTP 404 guessing.

- **Update Database**: `nikto -update`  
  Updates Nikto’s vulnerability database.

- **Check Database**: `nikto -h  -dbcheck`  
  Checks the scan database for errors.

### 3. **Output and Display Options**

- **Output Formats**:  
  - **HTML**: `nikto -h  -o output.html -Format html`  
  - **XML**: `nikto -h  -o output.xml -Format xml`  
  - **CSV**: `nikto -h  -o output.csv -Format csv`  
  - **Plain Text**: `nikto -h  -o output.txt`

- **Display Options**:  
  - **Verbose Output**: `nikto -h  -Display V`  
  - **Show HTTP Errors**: `nikto -h  -Display E`  
  - **Print to STDOUT**: `nikto -h  -Display P`

### 4. **Tuning and Customization**

- **Tuning Options**:  
  - **Upload Files**: `nikto -h  -tuning 0`  
  - **Remote File Retrieval**: `nikto -h  -tuning 7`  
  - **SQL Injection**: `nikto -h  -tuning 9`

- **Use Plugins**: `nikto -h  -Plugins `  
  Utilizes specified plugins during the scan.

- **Proxy Scan**: `nikto -h  -useproxy `  
  Performs scan via a proxy server.

### Additional References:
- https://hackviser.com/tactics/tools/nikto
- https://securemyorg.com/mastering-nikto-web-server-vulnerability-scanning/
- https://hackertarget.com/nikto-website-scanner/
- https://github.com/lattera/nikto/blob/master/nikto-1.x/nikto-1.36/docs/nikto_usage.txt

