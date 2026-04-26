# Web Application Testing References

## Vulnerable Servers
There are a series of vulnerable web applications that you can use to practice your skills in a safe environment. You can get more information about them in the [vulnerable-servers directory in this repository](https://github.com/The-Art-of-Hacking/art-of-hacking/tree/master/vulnerable-servers).

## API Security Assessment Tool

This repository includes a comprehensive **API Security Assessment Tool** that covers 9 critical security domains:

* **[api_security_assessment.py](api_security_assessment.py)** - Main assessment tool
* **[api_security_assessment_README.md](api_security_assessment_README.md)** - Detailed documentation
* **[api_security_example.py](api_security_example.py)** - Usage examples
* **[requirements_api_security.txt](requirements_api_security.txt)** - Dependencies

### Quick Start
```bash
# Install dependencies
pip install -r requirements_api_security.txt

# Basic assessment
python api_security_assessment.py --url https://api.example.com

# With authentication
python api_security_assessment.py --url https://api.example.com --token "Bearer your-token"
```

### Security Domains Tested
✅ Transport & TLS Security  
✅ Authentication Testing  
✅ Authorization Testing  
✅ Input Validation  
✅ SSRF Protection  
✅ Rate Limiting  
✅ Information Disclosure  
✅ Management Endpoints  
✅ CORS Configuration  

## A Few Popular Tools
The following are a few popular tools that you learned in the video courses part of these series:
* [Burp Suite](https://portswigger.net/burp)
* [OWASP Zed Attack Proxy (ZAP)](https://github.com/zaproxy/zaproxy)
* [sqlmap](http://sqlmap.org/)
* [httrack](https://www.httrack.com/)
* [skipfish](https://code.google.com/archive/p/skipfish/)
* [nikto](https://cirt.net/Nikto2)
* [ffuf](https://github.com/ffuf/ffuf) 

Article: [A Quick Guide to Using ffuf with Burp Suite](https://medium.com/@santosomar/a-quick-guide-to-using-ffuf-with-burp-suite-713492f62242)

## WebSploit

[WebSploit](https://websploit.h4cker.org/) is a virtual machine (VM) created by [Omar Santos](https://omarsantos.io) for different Cybersecurity Ethical Hacking (Web Penetration Testing) training sessions delivered at [DEFCON](https://www.wallofsheep.com/blogs/news/packet-hacking-village-workshops-at-def-con-26-finalized), [Live Training in Safari](https://www.safaribooksonline.com/search/?query=omar%20santos&extended_publisher_data=true&highlight=true&is_academic_institution_account=false&source=user&include_assessments=false&include_case_studies=true&include_courses=true&include_orioles=true&include_playlists=true&formats=live%20online%20training&sort=relevance), [video on demand LiveLessons](https://www.safaribooksonline.com/search/?query=omar%20santos&extended_publisher_data=true&highlight=true&is_academic_institution_account=false&source=user&include_assessments=false&include_case_studies=true&include_courses=true&include_orioles=true&include_playlists=true&formats=video&sort=relevance), and others. 

The purpose of this VM is to have a lightweight (single VM) with a few web application penetration testing tools, as well as vulnerable applications.


## How to Integrate OWASP ZAP with Jenkins
You can integrate ZAP with Jenkins and even automatically create Jira issues based on your findings. You can download the [ZAP plug in here](https://wiki.jenkins.io/display/JENKINS/zap+plugin).

[This video](https://www.youtube.com/watch?v=mmHZLSffCUg) provides an overview of how to integrate  

## Kubernetes Security
- [Kubernetes Pentest Methodology (part 1) by CyberArk](https://www.cyberark.com/threat-research-blog/kubernetes-pentest-methodology-part-1/)
- [Kubernetes Pentest Methodology (part 2) by CyberArk](https://www.cyberark.com/threat-research-blog/kubernetes-pentest-methodology-part-2/)
- [Kubernetes Pentest Methodology (part 2) by CyberArk](https://www.cyberark.com/threat-research-blog/kubernetes-pentest-methodology-part-3/)
- [Securing Kubernetes Clusters by Eliminating Risky Permissions](https://www.cyberark.com/threat-research-blog/securing-kubernetes-clusters-by-eliminating-risky-permissions/)
- [Kubernetes Network Policies Recipes](https://github.com/ahmetb/kubernetes-network-policy-recipes)
- [Kubiscan](https://github.com/cyberark/KubiScan)
- [Kube-hunter](https://github.com/aquasecurity/kube-hunter)
- [Kubernetes Goat](https://github.com/madhuakula/kubernetes-goat)


## Docker Security
- [OWASP Docker security resources](https://github.com/OWASP/Docker-Security)
- [Docker Bench for Security](https://github.com/docker/docker-bench-security)
- [Dockerscan](https://github.com/cr0hn/dockerscan)
- [Docker Security Playground](https://github.com/giper45/DockerSecurityPlayground)

## Javascript Tools
* [Retire.js](https://retirejs.github.io/retire.js)

## Popular Commercial Tools
* [Qualys Web Scanning](https://www.qualys.com/apps/web-app-scanning/)
* [IBM Security AppScan](https://www.ibm.com/security/application-security/appscan)

### XSS - Cross-Site Scripting

- [Cross-Site Scripting – Application Security – Google](https://www.google.com/intl/sw/about/appsecurity/learning/xss/) - Introduction to XSS by [Google](https://www.google.com/).
- [H5SC](https://github.com/cure53/H5SC) - HTML5 Security Cheatsheet - Collection of HTML5 related XSS attack vectors by [@cure53](https://github.com/cure53).
- [XSS.png](https://github.com/jackmasa/XSS.png) - XSS mind map by [@jackmasa](https://github.com/jackmasa).
- [EXCESS-XSS Guide](https://excess-xss.com/) - Comprehensive tutorial on cross-site scripting by [@JakobKallin](https://github.com/JakobKallin) and [Irene Lobo Valbuena](https://www.linkedin.com/in/irenelobovalbuena/).

### CSV Injection

- [CSV Injection -> Meterpreter on Pornhub](https://news.webamooz.com/wp-content/uploads/bot/offsecmag/147.pdf) - Written by [Andy](https://blog.zsec.uk/).
- [The Absurdly Underestimated Dangers of CSV Injection](http://georgemauer.net/2017/10/07/csv-injection.html) - Written by [George Mauer](http://georgemauer.net/).

### SQL Injection

- [SQL Injection Cheat Sheet](https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/) - Written by [@netsparker](https://twitter.com/netsparker).
- [SQL Injection Wiki](https://sqlwiki.netspi.com/) - Written by [NETSPI](https://www.netspi.com/).
- [SQL Injection Pocket Reference](https://websec.ca/kb/sql_injection) - Written by [@LightOS](https://twitter.com/LightOS).

### Command Injection

- [Potential command injection in resolv.rb](https://github.com/ruby/ruby/pull/1777) - Written by [@drigg3r](https://github.com/drigg3r).

### ORM Injection

- [HQL for pentesters](http://blog.h3xstream.com/2014/02/hql-for-pentesters.html) - Written by [@h3xstream](https://twitter.com/h3xstream/).
- [HQL : Hyperinsane Query Language (or how to access the whole SQL API within a HQL injection ?)](https://www.synacktiv.com/ressources/hql2sql_sstic_2015_en.pdf) - Written by [@_m0bius](https://twitter.com/_m0bius).
- [ORM2Pwn: Exploiting injections in Hibernate ORM](https://www.slideshare.net/0ang3el/orm2pwn-exploiting-injections-in-hibernate-orm) - Written by [Mikhail Egorov](https://0ang3el.blogspot.tw/).
- [ORM Injection](https://www.slideshare.net/simone.onofri/orm-injection) - Written by [Simone Onofri](https://onofri.org/).

### FTP Injection

- [Advisory: Java/Python FTP Injections Allow for Firewall Bypass](http://blog.blindspotsecurity.com/2017/02/advisory-javapython-ftp-injections.html) - Written by [Timothy Morgan](https://plus.google.com/105917618099766831589).
- [SMTP over XXE − how to send emails using Java's XML parser](https://shiftordie.de/blog/2017/02/18/smtp-over-xxe/) - Written by [Alexander Klink](https://shiftordie.de/).

### XXE - XML eXternal Entity

- [XXE](https://phonexicum.github.io/infosec/xxe.html) - Written by [@phonexicum](https://twitter.com/phonexicum).

### CSRF - Cross-Site Request Forgery

- [Wiping Out CSRF](https://medium.com/@jrozner/wiping-out-csrf-ded97ae7e83f) - Written by [@jrozner](https://medium.com/@jrozner).

### SSRF - Server-Side Request Forgery

- [SSRF bible. Cheatsheet](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit) - Written by [@Wallarm](https://twitter.com/wallarm).

### Rails

- [Rails Security - First part](https://hackmd.io/s/SkuTVw5O-) - Written by [@qazbnm456](https://github.com/qazbnm456).

### AngularJS

- [XSS without HTML: Client-Side Template Injection with AngularJS](http://blog.portswigger.net/2016/01/xss-without-html-client-side-template.html) - Written by [Gareth Heyes](https://www.blogger.com/profile/10856178524811553475).
- [DOM based Angular sandbox escapes](http://blog.portswigger.net/2017/05/dom-based-angularjs-sandbox-escapes.html) - Written by [@garethheyes](https://twitter.com/garethheyes)

### SSL/TLS

- [SSL & TLS Penetration Testing](https://www.aptive.co.uk/blog/tls-ssl-security-testing/) - Written by [APTIVE](https://www.aptive.co.uk/).

### Webmail

### NFS

- [NFS | PENETRATION TESTING ACADEMY](https://pentestacademy.wordpress.com/2017/09/20/nfs/?t=1&cn=ZmxleGlibGVfcmVjc18y&refsrc=email&iid=b34422ce15164e99a193fea0ccc7a02f&uid=1959680352&nid=244+289476616) - Written by [PENETRATION ACADEMY](https://pentestacademy.wordpress.com/).


### Fingerprint

### Sub Domain Enumeration

- [A penetration tester’s guide to sub-domain enumeration](https://blog.appsecco.com/a-penetration-testers-guide-to-sub-domain-enumeration-7d842d5570f6) - Written by [Bharath](https://blog.appsecco.com/@yamakira_).
- [The Art of Subdomain Enumeration](https://blog.sweepatic.com/art-of-subdomain-enumeration/) - Written by [Patrik Hudak](https://blog.sweepatic.com/author/patrik/).

### Crypto

- [Applied Crypto Hardening](https://bettercrypto.org/static/applied-crypto-hardening.pdf) - Written by [The bettercrypto.org Team](https://bettercrypto.org/).

### Web Shell

- [Hunting for Web Shells](https://www.tenable.com/blog/hunting-for-web-shells) - Written by [Jacob Baines](https://www.tenable.com/profile/jacob-baines).
- [Hacking with JSP Shells](https://blog.netspi.com/hacking-with-jsp-shells/) - Written by [@_nullbind](https://twitter.com/_nullbind).

### OSINT

- [Hacking Cryptocurrency Miners with OSINT Techniques](https://medium.com/@s3yfullah/hacking-cryptocurrency-miners-with-osint-techniques-677bbb3e0157) - Written by [@s3yfullah](https://medium.com/@s3yfullah).
- [OSINT x UCCU Workshop on Open Source Intelligence](https://www.slideshare.net/miaoski/osint-x-uccu-workshop-on-open-source-intelligence) - Written by [Philippe Lin](https://www.slideshare.net/miaoski).
- [102 Deep Dive in the Dark Web OSINT Style Kirby Plessas](https://www.youtube.com/watch?v=fzd3zkAI_o4) - Presented by [@kirbstr](https://twitter.com/kirbstr).


## Evasions

### CSP

- [CSP: bypassing form-action with reflected XSS](https://labs.detectify.com/2016/04/04/csp-bypassing-form-action-with-reflected-xss/) - Written by [Detectify Labs](https://labs.detectify.com/).
- [TWITTER XSS + CSP BYPASS](http://www.paulosyibelo.com/2017/05/twitter-xss-csp-bypass.html) - Written by [Paulos Yibelo](http://www.paulosyibelo.com/).

### WAF

- [Web Application Firewall (WAF) Evasion Techniques](https://medium.com/secjuice/waf-evasion-techniques-718026d693d8) - Written by [@secjuice](https://twitter.com/secjuice).
- [Web Application Firewall (WAF) Evasion Techniques #2](https://medium.com/secjuice/web-application-firewall-waf-evasion-techniques-2-125995f3e7b0) - Written by [@secjuice](https://twitter.com/secjuice).
- [Airbnb – When Bypassing JSON Encoding, XSS Filter, WAF, CSP, and Auditor turns into Eight Vulnerabilities](https://buer.haus/2017/03/08/airbnb-when-bypassing-json-encoding-xss-filter-waf-csp-and-auditor-turns-into-eight-vulnerabilities/) - Written by [@Brett Buerhaus](https://twitter.com/bbuerhaus).
- [How to bypass libinjection in many WAF/NGWAF](https://medium.com/@d0znpp/how-to-bypass-libinjection-in-many-waf-ngwaf-1e2513453c0f) - Written by [@d0znpp](https://medium.com/@d0znpp).

### JSMVC

- [JavaScript MVC and Templating Frameworks](http://www.slideshare.net/x00mario/jsmvcomfg-to-sternly-look-at-javascript-mvc-and-templating-frameworks) - Written by [Mario Heiderich](http://www.slideshare.net/x00mario).

### Authentication

- [Trend Micro Threat Discovery Appliance - Session Generation Authentication Bypass (CVE-2016-8584)](http://blog.malerisch.net/2017/04/trend-micro-threat-discovery-appliance-session-generation-authentication-bypass-cve-2016-8584.html) - Written by [@malerisch](https://twitter.com/malerisch) and [@steventseeley](https://twitter.com/steventseeley).
- [Yahoo Bug Bounty: Chaining 3 Minor Issues To Takeover Flickr Accounts](http://blog.mish.re/index.php/2017/04/29/yahoo-bug-bounty-chaining-3-minor-issues-to-takeover-flickr-accounts/) - Written by [Mishre](http://blog.mish.re/).

## Tricks

### CSRF

- [Neat tricks to bypass CSRF-protection](https://zhuanlan.zhihu.com/p/32716181) - Written by [Twosecurity](https://twosecurity.io/).
- [Exploiting CSRF on JSON endpoints with Flash and redirects](https://blog.appsecco.com/exploiting-csrf-on-json-endpoints-with-flash-and-redirects-681d4ad6b31b) - Written by [@riyazwalikar](https://blog.appsecco.com/@riyazwalikar).
- [Stealing CSRF tokens with CSS injection (without iFrames)](https://github.com/dxa4481/cssInjection) - Written by [@dxa4481](https://github.com/dxa4481).

### Remote Code Execution

- [Exploiting Node.js deserialization bug for Remote Code Execution](https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/) - Written by [OpSecX](https://opsecx.com/index.php/author/ajinabraham/).
- [DRUPAL 7.X SERVICES MODULE UNSERIALIZE() TO RCE](https://www.ambionics.io/blog/drupal-services-module-rce) - Written by [Ambionics Security](https://www.ambionics.io/).
- [How we exploited a remote code execution vulnerability in math.js](https://capacitorset.github.io/mathjs/) - Written by [@capacitorset](https://github.com/capacitorset).
- [GitHub Enterprise Remote Code Execution](http://exablue.de/blog/2017-03-15-github-enterprise-remote-code-execution.html) - Written by [@iblue](https://github.com/iblue).
- [How I Chained 4 vulnerabilities on GitHub Enterprise, From SSRF Execution Chain to RCE!](http://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html) - Written by [Orange](http://blog.orange.tw/).
- [How i Hacked into a PayPal's Server - Unrestricted File Upload to Remote Code Execution](http://blog.pentestbegins.com/2017/07/21/hacking-into-paypal-server-remote-code-execution-2017/) - Written by [Vikas Anil Sharma](http://blog.pentestbegins.com/).

### XSS

- [Query parameter reordering causes redirect page to render unsafe URL](https://hackerone.com/reports/293689) - Written by [kenziy](https://hackerone.com/kenziy).
- [ECMAScript 6 from an Attacker's Perspective - Breaking Frameworks, Sandboxes, and everything else](http://www.slideshare.net/x00mario/es6-en) - Written by [Mario Heiderich](http://www.slideshare.net/x00mario).
- [How I found a $5,000 Google Maps XSS (by fiddling with Protobuf)](https://medium.com/@marin_m/how-i-found-a-5-000-google-maps-xss-by-fiddling-with-protobuf-963ee0d9caff#.u50nrzhas) - Written by [@marin_m](https://medium.com/@marin_m).
- [DON'T TRUST THE DOM: BYPASSING XSS MITIGATIONS VIA SCRIPT GADGETS](https://www.blackhat.com/docs/us-17/thursday/us-17-Lekies-Dont-Trust-The-DOM-Bypassing-XSS-Mitigations-Via-Script-Gadgets.pdf) - Written by [Sebastian Lekies](https://twitter.com/slekies), [Krzysztof Kotowicz](https://twitter.com/kkotowicz), and [Eduardo Vela](https://twitter.com/sirdarckcat).
- [Uber XSS via Cookie](http://zhchbin.github.io/2017/08/30/Uber-XSS-via-Cookie/) - Written by [zhchbin](http://zhchbin.github.io/).
- [DOM XSS – auth.uber.com](http://stamone-bug-bounty.blogspot.tw/2017/10/dom-xss-auth_14.html) - Written by [StamOne_](http://stamone-bug-bounty.blogspot.tw/).
- [Stored XSS on Facebook](https://opnsec.com/2018/03/stored-xss-on-facebook/) - Written by [Enguerran Gillier](https://opnsec.com/).

### SQL Injection

- [MySQL Error Based SQL Injection Using EXP](https://www.exploit-db.com/docs/37953.pdf) - Written by [@osandamalith](https://twitter.com/osandamalith).
- [SQL injection in an UPDATE query - a bug bounty story!](http://zombiehelp54.blogspot.jp/2017/02/sql-injection-in-update-query-bug.html) - Written by [Zombiehelp54](http://zombiehelp54.blogspot.jp/).
- [GitHub Enterprise SQL Injection](http://blog.orange.tw/2017/01/bug-bounty-github-enterprise-sql-injection.html) - Written by [Orange](http://blog.orange.tw/).

### NoSQL Injection

- [GraphQL NoSQL Injection Through JSON Types](https://medium.com/@east5th/graphql-nosql-injection-through-json-types-a1a0a310c759) - Written by [@east5th](https://medium.com/@east5th).

### FTP Injection

- [XML Out-Of-Band Data Retrieval](https://media.blackhat.com/eu-13/briefings/Osipov/bh-eu-13-XML-data-osipov-slides.pdf) - Written by [@a66at](https://twitter.com/a66at) and Alexey Osipov.
- [XXE OOB exploitation at Java 1.7+](http://lab.onsec.ru/2014/06/xxe-oob-exploitation-at-java-17.html) - Written by [Ivan Novikov](http://lab.onsec.ru/).

### XXE

- [Evil XML with two encodings](https://mohemiv.com/all/evil-xml/) - Written by [Arseniy Sharoglazov](https://mohemiv.com/).

### SSRF

- [PHP SSRF Techniques](https://medium.com/secjuice/php-ssrf-techniques-9d422cb28d51) - Written by [@themiddleblue](https://medium.com/@themiddleblue).
- [SSRF in https://imgur.com/vidgif/url](https://hackerone.com/reports/115748) - Written by [aesteral](https://hackerone.com/aesteral).
- [A New Era of SSRF - Exploiting URL Parser in Trending Programming Languages!](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf) - Written by [Orange](http://blog.orange.tw/).
- [SSRF Tips](http://blog.safebuff.com/2016/07/03/SSRF-Tips/) - Written by [xl7dev](http://blog.safebuff.com/).

### Header Injection

- [Java/Python FTP Injections Allow for Firewall Bypass](http://blog.blindspotsecurity.com/2017/02/advisory-javapython-ftp-injections.html) - Written by [Timothy Morgan](https://plus.google.com/105917618099766831589).

### URL

- [Some Problems Of URLs](https://noncombatant.org/2017/11/07/problems-of-urls/) - Written by [Chris Palmer](https://noncombatant.org/about/).
- [Phishing with Unicode Domains](https://www.xudongz.com/blog/2017/idn-phishing/) - Written by [Xudong Zheng](https://www.xudongz.com/).
- [Unicode Domains are bad and you should feel bad for supporting them](https://www.vgrsec.com/post20170219.html) - Written by [VRGSEC](https://www.vgrsec.com/).
- [[dev.twitter.com] XSS](http://blog.blackfan.ru/2017/09/devtwittercom-xss.html) - Written by [Sergey Bobrov](http://blog.blackfan.ru/).



# AMAZING RESOURCES ABOUT WEB TECHNOLOGIES, FRAMEWORKS, PLATFORMS (hundreds of resources)

## Platforms

- [Node.js](https://github.com/sindresorhus/awesome-nodejs) - JavaScript runtime built on Chrome's V8 JavaScript engine.
- [Frontend Development](https://github.com/dypsilon/frontend-dev-bookmarks)
- [iOS](https://github.com/vsouza/awesome-ios) - Mobile operating system for Apple phones and tablets.
- [Android](https://github.com/JStumpp/awesome-android)
- [IoT & Hybrid Apps](https://github.com/weblancaster/awesome-IoT-hybrid)
- [Electron](https://github.com/sindresorhus/awesome-electron) - Cross-platform native desktop apps using JavaScript/HTML/CSS.
- [Cordova](https://github.com/busterc/awesome-cordova) - JavaScript API for hybrid apps.
- [React Native](https://github.com/jondot/awesome-react-native)
- [Xamarin](https://github.com/benoitjadinon/awesome-xamarin) - Mobile app development IDE, testing, and distribution.
- [Linux](https://github.com/aleksandar-todorovic/awesome-linux)
	- [Containers](https://github.com/Friz-zy/awesome-linux-containers)
- [macOS](https://github.com/iCHAIT/awesome-macOS)
	- [Command-Line](https://github.com/herrbischoff/awesome-osx-command-line)
	- [Screensavers](https://github.com/aharris88/awesome-macos-screensavers)
- [watchOS](https://github.com/yenchenlin/awesome-watchos) - Operating system for the Apple Watch.
- [JVM](https://github.com/deephacks/awesome-jvm)
- [Salesforce](https://github.com/mailtoharshit/awesome-salesforce)
- [Amazon Web Services](https://github.com/donnemartin/awesome-aws)
- [Windows](https://github.com/Awesome-Windows/Awesome)
- [IPFS](https://github.com/ipfs/awesome-ipfs) - P2P hypermedia protocol.
- [Fuse](https://github.com/vinkla/awesome-fuse) - Mobile development tools.
- [Heroku](https://github.com/ianstormtaylor/awesome-heroku) - Cloud platform as a service.
- [Raspberry Pi](https://github.com/thibmaek/awesome-raspberry-pi) - Credit card-sized computer aimed at teaching kids programming, but capable of a lot more.
- [Qt](https://github.com/JesseTG/awesome-qt) - Cross-platform GUI app framework.
- [WebExtensions](https://github.com/bfred-it/Awesome-WebExtensions) - Cross-browser extension system.
- [RubyMotion](https://github.com/motion-open-source/awesome-rubymotion) - Write cross-platform native apps for iOS, Android, macOS, tvOS, and watchOS in Ruby.
- [Smart TV](https://github.com/vitalets/awesome-smart-tv) - Create apps for different TV platforms.
- [GNOME](https://github.com/Kazhnuz/awesome-gnome) - Simple and distraction-free desktop environment for Linux.


## Programming Languages

- [JavaScript](https://github.com/sorrycc/awesome-javascript)
	- [Promises](https://github.com/wbinnssmith/awesome-promises)
	- [Standard Style](https://github.com/standard/awesome-standard) - Style guide and linter.
	- [Must Watch Talks](https://github.com/bolshchikov/js-must-watch)
	- [Tips](https://github.com/loverajoel/jstips)
	- [Network Layer](https://github.com/Kikobeats/awesome-network-js)
	- [Micro npm Packages](https://github.com/parro-it/awesome-micro-npm-packages)
	- [Mad Science npm Packages](https://github.com/feross/awesome-mad-science) - Impossible sounding projects that exist.
	- [Maintenance Modules](https://github.com/maxogden/maintenance-modules) - For npm packages.
	- [npm](https://github.com/sindresorhus/awesome-npm) - Package manager.
	- [AVA](https://github.com/avajs/awesome-ava) - Test runner.
	- [ESLint](https://github.com/dustinspecker/awesome-eslint) - Linter.
	- [Functional Programming](https://github.com/stoeffel/awesome-fp-js)
	- [Observables](https://github.com/sindresorhus/awesome-observables)
	- [npm scripts](https://github.com/RyanZim/awesome-npm-scripts) - Task runner.
- [Swift](https://github.com/matteocrippa/awesome-swift)
	- [Education](https://github.com/hsavit1/Awesome-Swift-Education)
	- [Playgrounds](https://github.com/uraimo/Awesome-Swift-Playgrounds)
- [Python](https://github.com/vinta/awesome-python)
	- [Asyncio](https://github.com/timofurrer/awesome-asyncio) - Asynchronous I/O in Python 3.
	- [Scientific Audio](https://github.com/faroit/awesome-python-scientific-audio) - Scientific research in audio/music.
- [Rust](https://github.com/rust-unofficial/awesome-rust)
- [Haskell](https://github.com/krispo/awesome-haskell)
- [PureScript](https://github.com/passy/awesome-purescript)
- [Go](https://github.com/avelino/awesome-go)
- [Scala](https://github.com/lauris/awesome-scala)
- [Ruby](https://github.com/markets/awesome-ruby)
	- [Events](https://github.com/planetruby/awesome-events)
- [Clojure](https://github.com/razum2um/awesome-clojure)
- [ClojureScript](https://github.com/hantuzun/awesome-clojurescript)
- [Elixir](https://github.com/h4cc/awesome-elixir)
- [Elm](https://github.com/isRuslan/awesome-elm)
- [Erlang](https://github.com/drobakowski/awesome-erlang)
- [Julia](https://github.com/svaksha/Julia.jl)
- [Lua](https://github.com/LewisJEllis/awesome-lua)
- [C](https://github.com/aleksandar-todorovic/awesome-c)
- [C/C++](https://github.com/fffaraz/awesome-cpp)
- [R](https://github.com/qinwf/awesome-R)
- [D](https://github.com/zhaopuming/awesome-d)
- [Common Lisp](https://github.com/CodyReichert/awesome-cl)
- [Perl](https://github.com/hachiojipm/awesome-perl)
- [Groovy](https://github.com/kdabir/awesome-groovy)
- [Dart](https://github.com/yissachar/awesome-dart)
- [Java](https://github.com/akullpp/awesome-java)
	- [RxJava](https://github.com/eleventigers/awesome-rxjava)
- [Kotlin](https://github.com/KotlinBy/awesome-kotlin)
- [OCaml](https://github.com/rizo/awesome-ocaml)
- [ColdFusion](https://github.com/seancoyne/awesome-coldfusion)
- [.NET](https://github.com/quozd/awesome-dotnet)
	- [Core](https://github.com/thangchung/awesome-dotnet-core)
- [PHP](https://github.com/ziadoz/awesome-php)
	- [Composer](https://github.com/jakoch/awesome-composer) - Package manager.
- [Delphi](https://github.com/Fr0sT-Brutal/awesome-delphi)
- [Assembler](https://github.com/jaspergould/awesome-asm)
- [AutoHotkey](https://github.com/ahkscript/awesome-AutoHotkey)
- [AutoIt](https://github.com/J2TeaM/awesome-AutoIt)
- [Crystal](https://github.com/veelenga/awesome-crystal)
- [Frege](https://github.com/sfischer13/awesome-frege) - Haskell for the JVM.
- [CMake](https://github.com/onqtam/awesome-cmake) - Build, test, and package software.
- [ActionScript 3](https://github.com/robinrodricks/awesome-actionscript3) - Object-oriented language targeting Adobe AIR.
- [Eta](https://github.com/sfischer13/awesome-eta) - Functional programming language for the JVM.
- [Idris](https://github.com/joaomilho/awesome-idris) - General purpose pure functional programming language with dependent types influenced by Haskell and ML.


## Front-End Development

- [ES6 Tools](https://github.com/addyosmani/es6-tools)
- [Web Performance Optimization](https://github.com/davidsonfellipe/awesome-wpo)
- [Web Tools](https://github.com/lvwzhen/tools)
- [CSS](https://github.com/sotayamashita/awesome-css)
	- [Critical-Path Tools](https://github.com/addyosmani/critical-path-css-tools)
	- [Scalability](https://github.com/davidtheclark/scalable-css-reading-list)
	- [Must-Watch Talks](https://github.com/AllThingsSmitty/must-watch-css)
	- [Protips](https://github.com/AllThingsSmitty/css-protips)
- [React](https://github.com/enaqx/awesome-react) - App framework.
	- [Relay](https://github.com/expede/awesome-relay) - Framework for building data-driven React apps.
- [Web Components](https://github.com/mateusortiz/webcomponents-the-right-way)
- [Polymer](https://github.com/Granze/awesome-polymer) - JavaScript library to develop Web Components.
- [Angular](https://github.com/gdi2290/awesome-angular) - App framework.
- [Backbone](https://github.com/sadcitizen/awesome-backbone) - App framework.
- [HTML5](https://github.com/diegocard/awesome-html5) - Markup language used for websites & web apps.
- [SVG](https://github.com/willianjusten/awesome-svg) - XML-based vector image format.
- [Canvas](https://github.com/raphamorim/awesome-canvas)
- [KnockoutJS](https://github.com/dnbard/awesome-knockout)
- [Dojo Toolkit](https://github.com/petk/awesome-dojo)
- [Inspiration](https://github.com/NoahBuscher/Inspire)
- [Ember](https://github.com/nmec/awesome-ember) - App framework.
- [Android UI](https://github.com/wasabeef/awesome-android-ui)
- [iOS UI](https://github.com/cjwirth/awesome-ios-ui)
- [Meteor](https://github.com/Urigo/awesome-meteor)
- [BEM](https://github.com/sturobson/BEM-resources)
- [Flexbox](https://github.com/afonsopacifer/awesome-flexbox)
- [Web Typography](https://github.com/deanhume/typography)
- [Web Accessibility](https://github.com/brunopulis/awesome-a11y)
- [Material Design](https://github.com/sachin1092/awesome-material)
- [D3](https://github.com/wbkd/awesome-d3) - Library for producing dynamic, interactive data visualizations.
- [Emails](https://github.com/jonathandion/awesome-emails)
- [jQuery](https://github.com/petk/awesome-jquery) - Easy to use JavaScript library for DOM manipulation.
	- [Tips](https://github.com/AllThingsSmitty/jquery-tips-everyone-should-know)
- [Web Audio](https://github.com/notthetup/awesome-webaudio)
- [Offline-First](https://github.com/pazguille/offline-first)
- [Static Website Services](https://github.com/aharris88/awesome-static-website-services)
- [A-Frame VR](https://github.com/aframevr/awesome-aframe) - Virtual reality for web browsers.
- [Cycle.js](https://github.com/cyclejs-community/awesome-cyclejs) - Functional and reactive JavaScript framework.
- [Text Editing](https://github.com/dok/awesome-text-editing)
- [Motion UI Design](https://github.com/fliptheweb/motion-ui-design)
- [Vue.js](https://github.com/vuejs/awesome-vue) - App framework.
- [Marionette.js](https://github.com/sadcitizen/awesome-marionette) - App framework.
- [Aurelia](https://github.com/behzad888/awesome-aurelia) - App framework.
- [Charting](https://github.com/zingchart/awesome-charting)
- [Ionic Framework 2](https://github.com/candelibas/awesome-ionic)
- [Chrome DevTools](https://github.com/ChromeDevTools/awesome-chrome-devtools)
- [PostCSS](https://github.com/jjaderg/awesome-postcss) - CSS tool.
- [Draft.js](https://github.com/nikgraf/awesome-draft-js) - Rich text editor framework for React.
- [Service Workers](https://github.com/TalAter/awesome-service-workers)
- [Progressive Web Apps](https://github.com/TalAter/awesome-progressive-web-apps)
- [choo](https://github.com/YerkoPalma/awesome-choo) - App framework.
- [Redux](https://github.com/brillout/awesome-redux) - State container for JavaScript apps.
- [webpack](https://github.com/webpack-contrib/awesome-webpack) - Module bundler.
- [Browserify](https://github.com/ungoldman/awesome-browserify) - Module bundler.
- [Sass](https://github.com/Famolus/awesome-sass) - CSS preprocessor.
- [Ant Design](https://github.com/websemantics/awesome-ant-design) - Enterprise-class UI design language.
- [Less](https://github.com/LucasBassetti/awesome-less) - CSS preprocessor.
- [WebGL](https://github.com/sjfricke/awesome-webgl) - JavaScript API for rendering 3D graphics.
- [Preact](https://github.com/ooade/awesome-preact) - App framework.
- [Progressive Enhancement](https://github.com/jbmoelker/progressive-enhancement-resources)
- [Next.js](https://github.com/unicodeveloper/awesome-nextjs) - Framework for server-rendered React apps.
- [Hyperapp](https://github.com/hyperapp/awesome-hyperapp) - Tiny JavaScript library for building web apps.


## Back-End Development

- [Django](https://github.com/rosarior/awesome-django)
- [Flask](https://github.com/humiaozuzu/awesome-flask)
- [Docker](https://github.com/veggiemonk/awesome-docker)
- [Vagrant](https://github.com/iJackUA/awesome-vagrant)
- [Pyramid](https://github.com/uralbash/awesome-pyramid)
- [Play1 Framework](https://github.com/PerfectCarl/awesome-play1)
- [CakePHP](https://github.com/friendsofcake/awesome-cakephp) - PHP framework.
- [Symfony](https://github.com/sitepoint/awesome-symfony)
	- [Education](https://github.com/pehapkari/awesome-symfony-education)
- [Laravel](https://github.com/chiraggude/awesome-laravel) - PHP framework.
	- [Education](https://github.com/fukuball/Awesome-Laravel-Education/blob/master/langs/en_US.md)
- [Rails](https://github.com/ekremkaraca/awesome-rails) - Web app framework for Ruby.
	- [Gems](https://github.com/hothero/awesome-rails-gem) - Packages.
- [Phalcon](https://github.com/phalcon/awesome-phalcon)
- [Useful `.htaccess` Snippets](https://github.com/phanan/htaccess)
- [nginx](https://github.com/fcambus/nginx-resources) - Web server.
- [Dropwizard](https://github.com/stve/awesome-dropwizard)
- [Kubernetes](https://github.com/ramitsurana/awesome-kubernetes)
- [Lumen](https://github.com/unicodeveloper/awesome-lumen)
- [Serverless Framework](https://github.com/JustServerless/awesome-serverless)
- [Apache Wicket](https://github.com/PhantomYdn/awesome-wicket) - Java web app framework.
- [Vert.x](https://github.com/vert-x3/vertx-awesome) - Toolkit for building reactive apps on the JVM.
- [Terraform](https://github.com/shuaibiyy/awesome-terraform) - Tool for building, changing, and versioning infrastructure.

## Databases

- [Database](https://github.com/numetriclabz/awesome-db)
- [MySQL](https://github.com/shlomi-noach/awesome-mysql/blob/gh-pages/index.md)
- [SQLAlchemy](https://github.com/dahlia/awesome-sqlalchemy)
- [InfluxDB](https://github.com/mark-rushakoff/awesome-influxdb)
- [Neo4j](https://github.com/neueda/awesome-neo4j)
- [MongoDB](https://github.com/ramnes/awesome-mongodb) - NoSQL database.
- [RethinkDB](https://github.com/d3viant0ne/awesome-rethinkdb)
- [TinkerPop](https://github.com/mohataher/awesome-tinkerpop) - Graph computing framework.
- [PostgreSQL](https://github.com/dhamaniasad/awesome-postgres) - Object-relational database.
- [CouchDB](https://github.com/quangv/awesome-couchdb) - Document-oriented NoSQL database.
- [HBase](https://github.com/rayokota/awesome-hbase) - Distributed, scalable, big data store.

## Content Management Systems

- [Umbraco](https://github.com/leekelleher/awesome-umbraco)
- [Refinery CMS](https://github.com/refinerycms-contrib/awesome-refinerycms) - Ruby on Rails CMS.
- [Wagtail](https://github.com/springload/awesome-wagtail) - Django CMS focused on flexibility and user experience.
- [Textpattern](https://github.com/drmonkeyninja/awesome-textpattern) - Lightweight PHP-based CMS.
- [Drupal](https://github.com/nirgn975/awesome-drupal) - Extensible PHP-based CMS.
- [Craft CMS](https://github.com/chasegiunta/awesome-craft) - Content-first CMS.
