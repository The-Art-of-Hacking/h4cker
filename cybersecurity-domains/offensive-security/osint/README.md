# Open-source Intelligence (OSINT)

Open Source Intelligence (OSINT) from an ethical hacking perspective involves the collection and analysis of information that is publicly available to identify vulnerabilities, gather data about targets, or understand the security posture of an organization. This process is a key initial phase in ethical hacking, also known as penetration testing or security auditing, where the goal is to enhance the security of the system or network being tested.

OSINT techniques are ethical and legal, involving the use of publicly accessible sources such as:

- **Public websites and forums**: Information from company websites, forums, and bulletin boards can provide insights into the technologies used, internal structure, and potential security weaknesses.
- **Social media platforms**: Public profiles and posts can reveal personal information about employees, organizational structure, and internal events that could be leveraged in social engineering attacks.
- **Government and public records**: Databases and records available from government agencies can provide information on domain registrations, patents, and more that are useful for mapping out an organization's online presence.
- **Search engines**: Advanced search engine techniques and dedicated tools can uncover hidden information and files related to a target that are available on the internet.
- **Open databases**: Databases like Shodan and Censys allow researchers to search for internet-connected devices, including potentially vulnerable systems exposed online.

The ethical use of OSINT means respecting privacy and legality, focusing on information that is publicly available without bypassing any access controls or engaging in activities that would be considered intrusive or illegal. Ethical hackers use OSINT to:

1. **Pre-assessment**: To understand the target's environment and identify potential points of entry before performing any active scanning or testing.
2. **Footprinting**: To gather as much information as possible about the target's digital and physical footprint.
3. **Vulnerability identification**: To find possible vulnerabilities in publicly accessible systems or applications that could be exploited.
4. **Social engineering preparation**: To collect data that could be used in crafting phishing campaigns or other social engineering tactics as part of a security assessment.

Ethical hackers document their findings and provide insights to organizations on how to mitigate any discovered vulnerabilities or security gaps, enhancing the overall security posture of the organization.

## Passive Recon Tools:
- [AMass](https://github.com/OWASP/Amass)
- [Deepinfo (commercial tool)](https://deepinfo.com)
- [EXIF Editor](https://exifeditor.io)
- [Exiftool](https://www.sno.phy.queensu.ca/~phil/exiftool/)
- [ExtractMetadata](http://www.extractmetadata.com)
- [Findsubdomains](https://findsubdomains.com/)
- [FOCA](https://elevenpaths.com)
- [IntelTechniques](https://inteltechniques.com)
- [Maltego](https://www.paterva.com/web7/)
- [Recon-NG](https://github.com/lanmaster53/recon-ng)
- [Scrapy](https://scrapy.org)
- [Screaming Frog](https://www.screamingfrog.co.uk)
- [Shodan](https://shodan.io)
- [SubdomainRadar](https://subdomainradar.io)
- [SpiderFoot](http://spiderfoot.net)
- [theHarvester](https://github.com/laramies/theHarvester)
- [Visual SEO Studio](https://visual-seo.com/)
- [Web Data Extractor](http://www.webextractor.com)
- [Xenu](http://home.snafu.de)
- [ParamSpider](https://github.com/devanshbatham/ParamSpider)
- [NullSec Tools](https://github.com/bad-antics/nullsec-tools) - Comprehensive security toolkit with OSINT modules for subdomain enumeration, email harvesting, social media reconnaissance, and metadata extraction.


## Open Source Threat Intelligence
- [Awesome Threat Intelligence](https://github.com/santosomar/awesome-threat-intelligence) - A curated list of awesome Threat Intelligence resources. This is a great resource and I try to contribute to it.

## OSINT Source Highlights
| Website             | Description        |
|---------------------|--------------------|
| shodan.io           | Server             |
| google.com          | Dorks              |
| wigle.net           | WiFi Networks      |
| grep.app            | Codes Search       |
| app.binaryedge      | Threat Intelligence|
| onyphe.io           | Server             |
| viz.greynoise.io    | Threat Intelligence|
| censys.io           | Server             |
| hunter.io           | Email Addresses    |
| fofa.info           | Threat Intelligence|
| zoomeye.org         | Threat Intelligence|
| leakix.net          | Threat Intelligence|
| intelx.io           | OSINT              |
| app.netlas.io       | Attack Surface     |
| searchcode.com      | Codes Search       |
| urlscan.io          | Threat Intelligence|
| publicwww.com       | Codes Search       |
| fullhunt.io         | Attack Surface     |
| socradar.io         | Threat Intelligence|
| binaryedge.io       | Attack Surface     |
| ivre.rocks          | Server             |
| crt.sh              | Certificate Search|
| vulners.com         | Vulnerabilities    |
| pulsedive.com       | Threat Intelligence|

### Website Exploration and "Google Hacking"
- censys : https://censys.io
- Certficate Search: https://crt.sh/
- ExifTool: https://www.sno.phy.queensu.ca/~phil/exiftool
- Google Hacking Database (GHDB): https://www.exploit-db.com/google-hacking-database
- Google Transparency Report: https://transparencyreport.google.com/https/certificates
- Huge TLS/SSL certificate DB with advanced search: https://certdb.com
- netcraft: https://searchdns.netcraft.com
- SiteDigger: http://www.mcafee.com/us/downloads/free-tools/sitedigger.aspx
- Spyse: https://spyse.com

### Data Breach Query Tools
- BaseQuery: https://github.com/g666gle/BaseQuery
- Buster: https://github.com/sham00n/buster
- h8mail: https://github.com/khast3x/h8mail
- Hudson Rock: https://www.hudsonrock.com/threat-intelligence-cybercrime-tools
- LeakLooker: https://github.com/woj-ciech/LeakLooker
- LeakRadar: https://leakradar.io
- PwnDB: https://github.com/davidtavarez/pwndb
- Scavenger: https://github.com/rndinfosecguy/Scavenger
- WhatBreach: https://github.com/Ekultek/WhatBreach

### IP address and DNS Lookup Tools
- [bgp](https://bgp.he.net/)
- [Bgpview](https://bgpview.io/)
- [DataSploit (IP Address Modules)](https://github.com/DataSploit/datasploit/tree/master/ip)
- [Domain Dossier](https://centralops.net/co/domaindossier.aspx)
- [Domaintoipconverter](http://domaintoipconverter.com/) 
- [Googleapps Dig](https://toolbox.googleapps.com/apps/dig/)
- [Hurricane Electric BGP Toolkit](https://bgp.he.net/)
- [ICANN Whois](https://whois.icann.org/en)
- [Massdns](https://github.com/blechschmidt/massdns) 
- [Mxtoolbox](https://mxtoolbox.com/BulkLookup.aspx)
- [Ultratools ipv6Info](https://www.ultratools.com/tools/ipv6Info)
- [Viewdns](https://viewdns.info/) 
- [Umbrella (OpenDNS) Popularity List](http://s3-us-west-1.amazonaws.com/umbrella-static/index.html) 

### Social Media
* [A tool to scrape LinkedIn](https://github.com/dchrastil/TTSL)
* [cree.py](https://github.com/ilektrojohn/creepy)

### Acquisitions and 
- [OCCRP Aleph](https://aleph.occrp.org/) - The global archive of research material for investigative reporting.
### Whois
WHOIS information is based upon a tree hierarchy. ICANN (IANA) is the authoritative registry for all of the TLDs and is a great starting point for all manual WHOIS queries.

- ICANN: http://www.icann.org
- IANA: http://www.iana.com
- NRO: http://www.nro.net
- AFRINIC: http://www.afrinic.net
- APNIC: http://www.apnic.net
- ARIN: http://ws.arin.net
- LACNIC: http://www.lacnic.net
- RIPE: http://www.ripe.net

### BGP looking glasses
- BGP4: http://www.bgp4.as/looking-glasses
- BPG6: http://lg.he.net/

### DNS
- dnsenum -	https://code.google.com/p/dnsenum
- dnsmap: https://code.google.com/p/dnsmap
- dnsrecon: https://www.darkoperator.com/tools-and-scripts
- dnstracer: https://www.mavetju.org/unix/dnstracer.php
- dnswalk: https://sourceforge.net/projects/dnswalk

## The OSINT Framework
- [OSINT Framework](https://osintframework.com)


## Dark Web OSINT Tools
### Dark Web Search Engine Tools
- [Ahmia Search Engine](https://ahmia.fi) and [their GitHub repo](https://github.com/ahmia/ahmia-site)
- [DarkSearch](https://darksearch.io) and their [GitHub repo](https://github.com/thehappydinoa/DarkSearch)
- [Katana](https://github.com/adnane-X-tebbaa/Katana)
- [OnionSearch](https://github.com/megadose/OnionSearch)
- [Search Engines for Academic Research](https://www.itseducation.asia/deep-web.htm)
- [DarkDump](https://github.com/josh0xA/darkdump)

### Tools to Obtain Information of .onion Links
- [H-Indexer](http://jncyepk6zbnosf4p.onion/onions.html)
- [Hunchly](https://www.hunch.ly/darkweb-osint)
- [Tor66 Fresh Onions](http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/fresh)

### Tools to scan onion links
- [Onioff](https://github.com/k4m4/onioff)
- [Onion-nmap](https://github.com/milesrichardson/docker-onion-nmap)
- [Onionscan](https://github.com/s-rah/onionscan)

### Tools to Crawl Dark Web Data
- [TorBot](https://github.com/DedSecInside/TorBot)
- [TorCrawl](https://github.com/MikeMeliz/TorCrawl.py)
- [OnionIngestor](https://github.com/danieleperera/OnionIngestor)

### Other Great Intelligence Gathering Sources and Tools
- Resources from Pentest-standard.org - http://www.pentest-standard.org/index.php/PTES_Technical_Guidelines#Intelligence_Gathering

### Active Recon
- Tons of references to scanners and vulnerability management software for active reconnaissance - http://www.pentest-standard.org/index.php/PTES_Technical_Guidelines#Vulnerability_Analysis
