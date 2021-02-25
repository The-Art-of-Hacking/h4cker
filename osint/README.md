# Open-source Intelligence (OSINT)

Open-source intelligence (OSINT) is data collected from open source and publicly available sources. The following are a few OSINT resources and references:

## Passive Recon Tools:
- [AMass](https://github.com/OWASP/Amass)
- [Buscador VM](https://inteltechniques.com/buscador)
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
- [SpiderFoot](http://spiderfoot.net)
- [theHarvester](https://github.com/laramies/theHarvester)
- [Visual SEO Studio](https://visual-seo.com/)
- [Web Data Extractor](http://www.webextractor.com)
- [Xenu](http://home.snafu.de)
- [ParamSpider](https://github.com/devanshbatham/ParamSpider)

## The OSINT Framework
- [OSINT Framework](https://osintframework.com)
- 
## Open Source Threat Intelligence

- [GOSINT](https://github.com/ciscocsirt/gosint) - a project used for collecting, processing, and exporting high quality indicators of compromise (IOCs). GOSINT allows a security analyst to collect and standardize structured and unstructured threat intelligence.
- [Awesome Threat Intelligence](https://github.com/santosomar/awesome-threat-intelligence) - A curated list of awesome Threat Intelligence resources. This is a great resource and I try to contribute to it.

## Active and Passive Reconnaissance Tips and Tools

### Passive Recon

#### Website Exploration and "Google Hacking"
* censys - https://censys.io
* Spyse - https://spyse.com
* netcraft - https://searchdns.netcraft.com
* Google Hacking Database (GHDB) - https://www.exploit-db.com/google-hacking-database
* ExifTool - https://www.sno.phy.queensu.ca/~phil/exiftool
* Certficate Search - https://crt.sh/
* Huge TLS/SSL certificate DB with advanced search - https://certdb.com
* Google Transparency Report - https://transparencyreport.google.com/https/certificates
* SiteDigger - http://www.mcafee.com/us/downloads/free-tools/sitedigger.aspx

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

#### Social Media
* A tool to scrape LinkedIn: https://github.com/dchrastil/TTSL
* cree.py	http://ilektrojohn.github.com/creepy

#### Whois
WHOIS information is based upon a tree hierarchy. ICANN (IANA) is the authoritative registry for all of the TLDs and is a great starting point for all manual WHOIS queries.
* ICANN - http://www.icann.org
* IANA - http://www.iana.com
* NRO - http://www.nro.net
* AFRINIC - http://www.afrinic.net
* APNIC - http://www.apnic.net
* ARIN - http://ws.arin.net
* LACNIC - http://www.lacnic.net
* RIPE - http://www.ripe.net

### BGP looking glasses
* BGP4 - http://www.bgp4.as/looking-glasses
* BPG6 - http://lg.he.net/

### DNS
* dnsenum -	http://code.google.com/p/dnsenum
* dnsmap - http://code.google.com/p/dnsmap
* dnsrecon - http://www.darkoperator.com/tools-and-scripts
* dnstracer - http://www.mavetju.org/unix/dnstracer.php
* dnswalk - http://sourceforge.net/projects/dnswalk

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
* Resources from Pentest-standard.org - http://www.pentest-standard.org/index.php/PTES_Technical_Guidelines#Intelligence_Gathering

### Active Recon
* Tons of references to scanners and vulnerability management software for active reconnaissance - http://www.pentest-standard.org/index.php/PTES_Technical_Guidelines#Vulnerability_Analysis
