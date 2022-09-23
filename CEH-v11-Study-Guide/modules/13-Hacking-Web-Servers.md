# Hacking Web Servers

## <u>Web Server Attack Methodology</u>

- **Information Gathering** - Internet searches, whois, reviewing robots.txt

- **Web  Server Footprinting** - banner grabbing
  - **Tools**
    - Netcraft
    - HTTPRecon
    - theHarvester
    - ID Serve
    - HTTPrint
    - nmap
      - `nmap --script http-trace -p80 localhost`
        - Detects vulnerable TRACE method
      - `nmap --script http-google-email <host>`
        -  Lists email addresses
      - `nmap --script hostmap-* <host>`
        - dDiscovers virtual hosts on the IP address you are trying to footprint; * is replaced by online db such as  IP2Hosts
      - `nmap --script http-enum -p80 <host>`
        - Enumerates common web apps
      - `nmap --script http-robots.txt -p 80 <host>`
        - Grabs the robots.txt file
        
- **Website Mirroring** - brings the site to your own machine to examine structure, etc.
  - **Tools**
    - Wget
    - BlackWidow
    - HTTrack
    - WebCopier Pro
    - Web Ripper
    - SurfOffline

- **Vulnerability Scanning** - scans web server for vulnerabilities
  - **Tools**
    - Nessus
    - Nikto - specifically suited for web servers; still very noisy like Nessus

- **Session Hijacking**

- **Web Server Password Cracking**

## <u>Web Server Architecture</u>

- **Most Popular Servers** - Apache, Microsoft IIS and Nginx
  - Apache runs configurations as a part of a module within special files (http.conf, etc.)
  - IIS runs all applications in the context of LOCAL_SYSTEM
  - IIS 5 had a ton of bugs - easy to get into
- **N-Tier Architecture** - distributes processes across multiple servers; normally as three-tier: Presentation (web), logic (application) and data (database)
- **Error Reporting** - should not be showing errors in production; easy to glean information
- **HTML** - markup language used to display web pages
- **HTTP Request Methods**
  - **GET** - retrieves whatever information is in the URL; sending data is done in URL
  - **HEAD** - identical to get except for no body return
  - **POST** - sends data via body - data not shown in URL or in history
  - **PUT** - requests data be stored at the URL
  - **DELETE** - requests origin server delete resource
  - **TRACE** - requests application layer loopback of message
  - **CONNECT** - reserved for use with proxy
  - Both POST and GET can be manipulated by a web proxy
- **HTTP Error Messages**
  - **1xx: Informational** - request received, continuing
  - **2xx: Success** - action received, understood and accepted
  - **3xx: Redirection** - further action must be taken
  - **4xx: Client Error** - request contains bad syntax or cannot be fulfilled
  - **5xx: Server Error** - server failed to fulfill an apparently valid request

## <u>Web Server Attacks</u>

- **DNS Amplification** - Uses recursive DNS to DoS a target; amplifies DNS answers to target until it can't do anything

- **Directory Transversal** (../ or dot-dot-slash) - requests file that should not be accessible from web server
  - Example: http://www.example.com/../../../../etc/password
  - Can use Unicode to possibly evade IDS - %2e for dot and %sf for slash

- **Parameter Tampering** (URL Tampering) - Manipulating parameters within URL to achieve escalation or other changes

- **Hidden Field Tampering** - Modifying hidden form fields producing unintended results

- **HTTP Response Splitting** - An attacker passes malicious data to a vulnerable application through the HTTP response header.

- **Web Cache Poisoning** - Replacing the cache on a box with a malicious version of it

- **WFETCH** - Microsoft tool that allows you to craft HTTP requests to see response data

- **Misconfiguration Attack** - Same as before - improper configuration of a web server. (e.g: Default settings like admin/password credentials; Lack of security controls)

- **Password Attack** - Attempting to crack passwords related to web resources

- **Connection String Parameter Pollution** - Injection attack that uses semicolons to take advantage of databases that use this separation method

- **Web Defacement** - Simply modifying a web page to say something else

- **DoS/DDoS** - Compromise availability 

- **Shellshock** - Causes Bash to unintentionally execute commands when commands are concatenated on the end of function definitions

- **Tools**
  - **Brutus** - brute force web passwords of HTTP
  - **Hydra** - network login cracker
  - **Metasploit**
    - Basic working is Libraries use Interfaces and Modules to send attacks to services
    - **Exploits** hold the actual exploit
    - **Payload** contains the arbitrary code if exploit is successful
    - **Auxiliary** used for one-off actions (like a scan)
    - **NOPS** used for buffer-overflow type operations
