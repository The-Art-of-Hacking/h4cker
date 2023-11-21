# Cloud Security Resources

* [Cloud Security Resources from AWS](https://aws.amazon.com/security/security-resources)
* [Penetration Testing Rules of Engagement in Microsoft Azure](https://www.microsoft.com/en-us/msrc/pentest-rules-of-engagement)
* [Penetration Testing in AWS](https://aws.amazon.com/security/penetration-testing)
* [Penetration Testing in Google Cloud Platform and Cloud Security FAQ](https://support.google.com/cloud/answer/6262505)
* [Google Cloud Security Center](https://cloud.google.com/security)
* [High-level Best Practices when Performing Pen Testing in Cloud Environments](high_level_best_practices_pen_testing.md)

## Vulnerables
- [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat)
- [Damn Vulnerable Cloud Application(DVCA)](https://github.com/m6a-UdS/dvca)
- [PENETRATION TESTING AWS STORAGE: KICKING THE S3 BUCKET](https://rhinosecuritylabs.com/penetration-testing/penetration-testing-aws-storage/) - Written by Dwight Hohnstein from [Rhino Security Labs](https://rhinosecuritylabs.com/).

## Additional Tools
- [Taken - Takeover AWS Ips And Have A Working POC For Subdomain Takeover](http://feedproxy.google.com/~r/PentestTools/~3/bOdrVajU9Ns/taken-takeover-aws-ips-and-have-working.html)
- [Autovpn - Create On Demand Disposable OpenVPN Endpoints On AWS](http://feedproxy.google.com/~r/PentestTools/~3/lxGVU3oWwCE/autovpn-create-on-demand-disposable.html)
- [SpaceSiren - A Honey Token Manager And Alert System For AWS](http://feedproxy.google.com/~r/PentestTools/~3/SIBlEXl2Mhc/spacesiren-honey-token-manager-and.html)
- [AWS Recon - Multi-threaded AWS Inventory Collection Tool With A Focus On Security-Relevant Resources And Metadata](http://feedproxy.google.com/~r/PentestTools/~3/mCRMljaSu2w/aws-recon-multi-threaded-aws-inventory.html)
- [DAGOBAH - Open Source Tool To Generate Internal Threat Intelligence, Inventory & Compliance Data From AWS Resources](http://feedproxy.google.com/~r/PentestTools/~3/heCluXrDIA0/dagobah-open-source-tool-to-generate.html)
- [AWS Report - A Tool For Analyzing Amazon Resources](http://feedproxy.google.com/~r/PentestTools/~3/pKUBrpmSvbE/aws-report-tool-for-analyzing-amazon.html)
- [SkyArk - Helps To Discover, Assess And Secure The Most Privileged Entities In Azure And AWS](http://feedproxy.google.com/~r/PentestTools/~3/fA1njXZatyo/skyark-helps-to-discover-assess-and.html)
- [Cloudsplaining - An AWS IAM Security Assessment Tool That Identifies Violations Of Least Privilege And Generates A Risk-Prioritized Report](http://feedproxy.google.com/~r/PentestTools/~3/-7enjmYyTw8/cloudsplaining-aws-iam-security.html)
- [SkyWrapper - Tool That Helps To Discover Suspicious Creation Forms And Uses Of Temporary Tokens In AWS](http://feedproxy.google.com/~r/PentestTools/~3/w0otGurmXTY/skywrapper-tool-that-helps-to-discover.html)
- [Sandcastle - A Python Script For AWS S3 Bucket Enumeration](http://feedproxy.google.com/~r/PentestTools/~3/e2xzlmFDtaE/sandcastle-python-script-for-aws-s3.html)
- [Awspx - A Graph-Based Tool For Visualizing Effective Access And Resource Relationships In AWS Environments](http://feedproxy.google.com/~r/PentestTools/~3/S_VHOWSjPYM/awspx-graph-based-tool-for-visualizing.html)
- [AWSGen.py - Generates Permutations, Alterations And Mutations Of AWS S3 Buckets Names](http://feedproxy.google.com/~r/PentestTools/~3/SagQLMEKNHs/awsgenpy-generates-permutations.html)
- [AlertResponder - Automatic Security Alert Response Framework By AWS Serverless Application Model](http://feedproxy.google.com/~r/PentestTools/~3/Wz_C66kvWFE/alertresponder-automatic-security-alert.html)
- [Aaia - AWS Identity And Access Management Visualizer And Anomaly Finder](http://feedproxy.google.com/~r/PentestTools/~3/2yvKL6xqlqM/aaia-aws-identity-and-access-management.html)
- [FireProx - AWS API Gateway Management Tool For Creating On The Fly HTTP Pass-Through Proxies For Unique IP Rotation](http://feedproxy.google.com/~r/PentestTools/~3/TkQaYYrkjO8/fireprox-aws-api-gateway-management.html)

## Azure
### Enumeration Tools
#### Email and Username Enumeration
- [o365creeper](https://github.com/LMGsec/o365creeper) - Enumerate valid email addresses
- [Office 365 User Enumeration](https://github.com/gremwell/o365enum) - Enumerate valid usernames from Office 365

#### Cloud Infrastructure Enumeration
- [CloudBrute](https://github.com/0xsha/CloudBrute) - Find a cloud infrastructure of a company
- [cloud_enum](https://github.com/initstring/cloud_enum) - Multi-cloud OSINT tool
- [Azucar](https://github.com/nccgroup/azucar) - Security auditing tool for Azure environments

#### Azure Specific Enumeration
- [BlobHunter](https://github.com/cyberark/blobhunter) - Scanning Azure blob storage accounts
- [Grayhat Warfare](https://buckets.grayhatwarfare.com/) - Open Azure blobs search
- [Azure-AccessPermissions](https://github.com/csandker/Azure-AccessPermissions) - Enumerate access permissions in Azure AD

### Information Gathering Tools
#### Azure Information Gathering
- [o365recon](https://github.com/nyxgeek/o365recon) - Information gathering with valid credentials to Azure
- [Azurite](https://github.com/FSecureLABS/Azurite) - Enumeration and reconnaissance in Microsoft Azure Cloud
- [Sparrow.ps1](https://github.com/cisagov/Sparrow) - Detect possible compromised accounts in Azure/M365
- [Microsoft Azure AD Assessment](https://github.com/AzureAD/AzureADAssessment) - Assessing Azure AD tenant state

#### Multi-Cloud Security Auditing
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) - Multi-cloud security auditing tool
- [Prowler](https://github.com/prowler-cloud/prowler) - AWS and Azure security assessments

### Lateral Movement Tools
- [Stormspotter](https://github.com/Azure/Stormspotter) - Azure Red Team tool
- [AzureADLateralMovement](https://github.com/talmaor/AzureADLateralMovement) - Lateral Movement graph for Azure AD
- [SkyArk](https://github.com/cyberark/SkyArk) - Privileged entities in Azure and AWS

### Exploitation Tools
#### Azure Exploitation
- [MicroBurst](https://github.com/NetSPI/MicroBurst) - Scripts for assessing Microsoft Azure security
- [Microsoft-Teams-GIFShell](https://github.com/bobbyrsec/Microsoft-Teams-GIFShell) - Microsoft Teams reverse shell execution

#### Credential Attacks
- [MSOLSpray](https://github.com/dafthack/MSOLSpray) - Password spraying tool for Microsoft Online accounts
- [MFASweep](https://github.com/dafthack/MFASweep) - Check if MFA is enabled on multiple Microsoft Services Resources
- [adconnectdump](https://github.com/fox-it/adconnectdump) - Dump Azure AD Connect credentials

## Resources
### Articles
- [Abusing Azure AD SSO with the Primary Refresh Token ](https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/)
- [Abusing dynamic groups in Azure AD for Privilege Escalation](https://www.mnemonic.no/blog/abusing-dynamic-groups-in-azure/)
- [Attacking Azure, Azure AD, and Introducing PowerZure](https://hausec.com/2020/01/31/attacking-azure-azure-ad-and-introducing-powerzure/)
- [Attacking Azure & Azure AD, Part II](https://posts.specterops.io/attacking-azure-azure-ad-part-ii-5f336f36697d)
- [Azure AD Connect for Red Teamers](https://blog.xpnsec.com/azuread-connect-for-redteam/)
- [Azure AD Introduction for Red Teamers](https://www.synacktiv.com/posts/pentest/azure-ad-introduction-for-red-teamers.html)
- [Azure AD Pass The Certificate](https://medium.com/@mor2464/azure-ad-pass-the-certificate-d0c5de624597)
- [Azure AD privilege escalation - Taking over default application permissions as Application Admin](https://dirkjanm.io/azure-ad-privilege-escalation-application-admin/)
- [Defense and Detection for Attacks Within Azure](https://posts.specterops.io/detecting-attacks-within-azure-bdc40f8c0766)
- [Hunting Azure Admins for Vertical Escalation](https://www.lares.com/blog/hunting-azure-admins-for-vertical-escalation/)
- [Impersonating Office 365 Users With Mimikatz](https://www.dsinternals.com/en/impersonating-office-365-users-mimikatz/)
- [Lateral Movement from Azure to On-Prem AD](https://posts.specterops.io/death-from-above-lateral-movement-from-azure-to-on-prem-ad-d18cb3959d4d)
- [Malicious Azure AD Application Registrations](https://www.lares.com/blog/malicious-azure-ad-application-registrations/)
- [Moving laterally between Azure AD joined machines](https://medium.com/@talthemaor/moving-laterally-between-azure-ad-joined-machines-ed1f8871da56)
- [CrowdStrike Launches Free Tool to Identify and Help Mitigate Risks in Azure Active Directory](https://www.crowdstrike.com/blog/crowdstrike-launches-free-tool-to-identify-and-help-mitigate-risks-in-azure-active-directory/)
- [Privilege Escalation Vulnerability in Azure Functions](https://www.intezer.com/blog/cloud-security/royal-flush-privilege-escalation-vulnerability-in-azure-functions/)
- [Azure Application Proxy C2](https://www.trustedsec.com/blog/azure-application-proxy-c2/)
- [Recovering Plaintext Passwords from Azure Virtual Machines like It’s the 1990s](https://www.guardicore.com/labs/recovering-plaintext-passwords-azure/)
- [Forensicating Azure VMs](https://isc.sans.edu/forums/diary/Forensicating+Azure+VMs/27136/)
- [Network Forensics on Azure VMs](https://isc.sans.edu/forums/diary/Network+Forensics+on+Azure+VMs+Part+1/27536/)
- [Cross-Account Container Takeover in Azure Container Instances](https://unit42.paloaltonetworks.com/azure-container-instances/)
- [Azure Active Directory password brute-forcing flaw](https://arstechnica.com/information-technology/2021/09/new-azure-active-directory-password-brute-forcing-flaw-has-no-fix/)
- [How to Detect Azure Active Directory Backdoors: Identity Federation](https://www.inversecos.com/2021/11/how-to-detect-azure-active-directory.html)
- [Azure App Service vulnerability exposed hundreds of source code repositories](https://blog.wiz.io/azure-app-service-source-code-leak/)
- [AutoWarp: Cross-Account Vulnerability in Microsoft Azure Automation Service](https://orca.security/resources/blog/autowarp-microsoft-azure-automation-service-vulnerability/)
- [Microsoft Azure Synapse Pwnalytics](https://medium.com/tenable-techblog/microsoft-azure-synapse-pwnalytics-87c99c036291)
- [Microsoft Azure Site Recovery DLL Hijacking](https://medium.com/tenable-techblog/microsoft-azure-site-recovery-dll-hijacking-cd8cc34ef80c)
- [FabriXss (CVE-2022-35829): Abusing a Custom Role User Using CSTI and Stored XSS in Azure Fabric Explorer](https://orca.security/resources/blog/fabrixss-vulnerability-azure-fabric-explorer/)
- [Untangling Azure Active Directory Principals & Access Permissions](https://csandker.io/2022/10/19/Untangling-Azure-Permissions.html)
- [How to Detect OAuth Access Token Theft in Azure](https://www.inversecos.com/2022/08/how-to-detect-oauth-access-token-theft.html)
- [How to deal with Ransomware on Azure](https://sysdig.com/blog/ransomware-azure-mitigations/)
- [How Orca found Server-Side Request Forgery (SSRF) Vulnerabilities in four different Azure Services](https://orca.security/resources/blog/ssrf-vulnerabilities-in-four-azure-services/)
- [EmojiDeploy: Smile! Your Azure web service just got RCE’d](https://ermetic.com/blog/azure/emojideploy-smile-your-azure-web-service-just-got-rced)
- [Bounce the Ticket and Silver Iodide on Azure AD Kerberos](https://www.silverfort.com/resources/white-paper/bounce-the-ticket-and-silver-iodide-on-azure-ad-kerberos/)

#### Lists and Cheat Sheets
- [List of all Microsoft Portals](https://msportals.io/)
- [Azure Articles from NetSPI](https://blog.netspi.com/?s=azure)
- [Azure Cheat Sheet on CloudSecDocs](https://cloudsecdocs.com/azure/services/overview/)
- [Resources about Azure from Cloudberry Engineering](https://cloudberry.engineering/tags/azure/)
- [Resources from PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Cloud%20-%20Azure%20Pentest.md)
- [Encyclopedia on Hacking the Cloud](https://hackingthe.cloud/)
- [Azure AD - Attack and Defense Playbook](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense)
- [Azure Security Resources and Notes](https://github.com/rootsecdev/Azure-Red-Team)
- [Azure Threat Research Matrix](https://microsoft.github.io/Azure-Threat-Research-Matrix/)

### Lab Exercises
- [azure-security-lab](https://github.com/azurecitadel/azure-security-lab) - Securing Azure Infrastructure - Hands on Lab Guide
- [AzureSecurityLabs](https://github.com/davisanc/AzureSecurityLabs) - Hands-on Security Labs focused on Azure IaaS Security
- [Building Free Active Directory Lab in Azure](https://medium.com/@kamran.bilgrami/ethical-hacking-lessons-building-free-active-directory-lab-in-azure-6c67a7eddd7f)
- [Aria Cloud Penetration Testing Tools Container](https://github.com/iknowjason/AriaCloud) - A Docker container for remote penetration testing
- [PurpleCloud](https://github.com/iknowjason/PurpleCloud) - Multi-use Hybrid + Identity Cyber Range implementing a small Active Directory Domain in Azure alongside Azure AD and Azure Domain Services
- [BlueCloud](https://github.com/iknowjason/BlueCloud) - Cyber Range system with a Windows VM for security testing with Azure and AWS Terraform support
- [Azure Red Team Attack and Detect Workshop](https://github.com/mandiant/Azure_Workshop)
- [SANS Workshop – Building an Azure Pentest Lab for Red Teams](https://www.sans.org/webcasts/sans-workshop-building-azure-pentest-lab-red-teams/) - The link in the description contains a password-protected OVA file that can be used until 2nd March 2024

### Talks and Videos
- [Attacking and Defending the Microsoft Cloud (Office 365 & Azure AD](https://www.youtube.com/watch?v=SG2ibjuzRJM)
  - [Presentation Slides](https://i.blackhat.com/USA-19/Wednesday/us-19-Metcalf-Attacking-And-Defending-The-Microsoft-Cloud.pdf)
- [TR19: I'm in your cloud, reading everyone's emails - hacking Azure AD via Active Directory](https://www.youtube.com/watch?v=JEIR5oGCwdg)
  - [Presentation Slides](https://troopers.de/downloads/troopers19/TROOPERS19_AD_Im_in_your_cloud.pdf)
- [Dirk Jan Mollema - Im In Your Cloud Pwning Your Azure Environment - DEF CON 27 Conference](https://www.youtube.com/watch?v=xei8lAPitX8)
  - [Presentation Slides](https://media.defcon.org/DEF%20CON%2027/DEF%20CON%2027%20presentations/DEFCON-27-Dirk-jan-Mollema-Im-in-your-cloud-pwning-your-azure-environment.pdf)
- [Adventures in Azure Privilege Escalation Karl Fosaaen](https://www.youtube.com/watch?v=EYtw-XPml0w)
  - [Presentation Slides](https://notpayloads.blob.core.windows.net/slides/Azure-PrivEsc-DerbyCon9.pdf)
- [Introducing ROADtools - Azure AD exploration for Red Teams and Blue Teams](https://www.youtube.com/watch?v=o5QDt30Pw_o)


## Public Cloud Governance
### AWS Governance
* [AWS CloudFormation Guard](https://github.com/aws-cloudformation/cloudformation-guard)
* [AWS CodePipeline Governance](https://github.com/awslabs/aws-codepipeline-governance)
* [AWS Config Rules Development Kit](https://github.com/awslabs/aws-config-rdklib)
* [AWS Control Tower Customizations](https://github.com/awslabs/aws-control-tower-customizations)
* [AWS Security Hub Automated Response and Remediation](https://github.com/awslabs/aws-security-hub-automated-response-and-remediation)
* [AWS Vault](https://github.com/99designs/aws-vault)
* [AWS Well Architected Labs](https://github.com/awslabs/aws-well-architected-labs)

* ## AWS - Patterns

### URL Services

| Service      | URL                   |
|--------------|-----------------------|
| s3           | https://{user_provided}.s3.amazonaws.com |
| cloudfront   | https://{random_id}.cloudfront.net |
| ec2          | ec2-{ip-seperated}.compute-1.amazonaws.com |
| es           | https://{user_provided}-{random_id}.{region}.es.amazonaws.com |
| elb          | http://{user_provided}-{random_id}.{region}.elb.amazonaws.com:80/443 |
| elbv2        | https://{user_provided}-{random_id}.{region}.elb.amazonaws.com |
| rds          | mysql://{user_provided}.{random_id}.{region}.rds.amazonaws.com:3306 |
| rds          | postgres://{user_provided}.{random_id}.{region}.rds.amazonaws.com:5432 |
| route 53     | {user_provided} |
| execute-api  | https://{random_id}.execute-api.{region}.amazonaws.com/{user_provided} |
| cloudsearch  | https://doc-{user_provided}-{random_id}.{region}.cloudsearch.amazonaws.com |
| transfer     | sftp://s-{random_id}.server.transfer.{region}.amazonaws.com |
| iot          | mqtt://{random_id}.iot.{region}.amazonaws.com:8883 |
| iot          | https://{random_id}.iot.{region}.amazonaws.com:8443 |
| iot          | https://{random_id}.iot.{region}.amazonaws.com:443 |
| mq           | https://b-{random_id}-{1,2}.mq.{region}.amazonaws.com:8162 |
| mq           | ssl://b-{random_id}-{1,2}.mq.{region}.amazonaws.com:61617 |
| kafka        | b-{1,2,3,4}.{user_provided}.{random_id}.c{1,2}.kafka.{region}.amazonaws.com |
| kafka        | {user_provided}.{random_id}.c{1,2}.kafka.useast-1.amazonaws.com |
| cloud9       | https://{random_id}.vfs.cloud9.{region}.amazonaws.com |
| mediastore   | https://{random_id}.data.mediastore.{region}.amazonaws.com |
| kinesisvideo | https://{random_id}.kinesisvideo.{region}.amazonaws.com |
| mediaconvert | https://{random_id}.mediaconvert.{region}.amazonaws.com |
| mediapackage | https://{random_id}.mediapackage.{region}.amazonaws.com/in/v1/{random_id}/channel |
### MultiCloud Governance
* [Cloud Custodian](https://github.com/cloud-custodian/cloud-custodian)
* [CloudQuary](https://github.com/cloudquery/cloudquery)
* [Cloudsploit](https://github.com/aquasecurity/cloudsploit)
* [ManageIQ by RedHat](https://github.com/ManageIQ/manageiq)
* [Mist.io](https://github.com/mistio/mist-ce)
* [NeuVector](https://github.com/neuvector/neuvector)
* [Triton by Joyent](https://github.com/joyent/triton)
## Kubernetes Operators
* Aqua
  * [Aqua Security Operator](https://operatorhub.io/operator/aqua)
  * [Starboard Operator](https://operatorhub.io/operator/starboard-operator)
* Misc
  * [Anchore - Anchore Engine Operator](https://operatorhub.io/operator/anchore-engine)
  * [Falco Security - Falco Operator](https://operatorhub.io/operator/falco)
  * [Quay - Project Quay Container Security](https://operatorhub.io/operator/project-quay-container-security-operator)
  * [Snyk - Snyk Operator](https://operatorhub.io/operator/snyk-operator)
  * [Splunk - Splunk Operator for Kubernetes](https://operatorhub.io/operator/splunk)
  * [Sysdig - Sysdig Agent Operator](https://operatorhub.io/operator/sysdig)

## Container Tools
* Anchore
  * [Anchore Engine](https://github.com/anchore/anchore-engine)
  * [Grype](https://github.com/anchore/grype)
  * [Kai](https://github.com/anchore/kai)
  * [Syft](https://github.com/anchore/syft)
* Aqua
  * [Cloudsploit](https://github.com/aquasecurity/cloudsploit)
  * [Kube-Bench](https://github.com/aquasecurity/kube-bench)
  * [Kube-Hunter](https://github.com/aquasecurity/kube-hunter)
  * [Kubectl-who-can](https://github.com/aquasecurity/kubectl-who-can)
  * [Trivy](https://github.com/aquasecurity/trivy)
* Misc
  * [Docker - Docker Bench for Security](https://github.com/docker/docker-bench-security)
  * [Elias - Dagda](https://github.com/eliasgranderubio/dagda/)
  * [Falco Security - Falco](https://github.com/falcosecurity/falco)
  * [Harbor - Harbor](https://github.com/goharbor/harbor)
  * [Quay - Clair](https://github.com/quay/clair)
  * [Snyk - Snyk](https://github.com/snyk/snyk)
  * [vchinnipilli - Kubestriker](https://github.com/vchinnipilli/kubestriker)

## Cloud Security Standards
* [ISO/IEC 27017:2015](https://www.iso.org/standard/43757.html)
* [ISO/IEC 27018:2019](https://www.iso.org/standard/76559.html)
* [MTCS SS 584](https://www.imda.gov.sg/industry-development/infrastructure/ict-standards-and-frameworks/mtcs-certification-scheme/multi-tier-cloud-security-certified-cloud-services)
* [CCM](https://cloudsecurityalliance.org/group/cloud-controls-matrix)
* [NIST 800-53](https://nvd.nist.gov/800-53)
## Learning
### Blogs
* [AWS Security](https://aws.amazon.com/blogs/security/)
* [Azure Security](https://www.microsoft.com/security/blog/azure-security/)
* [Dark Reading](https://www.darkreading.com/cloud-security.asp)
### Courses
* Oracle
  * [Oracle Cloud Security Administrator](https://learn.oracle.com/ols/learning-path/become-a-cloud-security-administrator/35644/38707)
* A Cloud Guru
  * Learning Paths
    * [AWS Security Path](https://learn.acloud.guru/learning-path/aws-security)
    * [Azure Security Path](https://learn.acloud.guru/learning-path/azure-security)
    * [GCP Security Path](https://learn.acloud.guru/learning-path/gcp-security)
### Labs
* [AWS Workshops](https://workshops.aws/categories/Security)
  * [AWS Identity: Using Amazon Cognito for serverless consumer apps](https://serverless-idm.awssecworkshops.com/)
  * [AWS Network Firewall Workshop](https://networkfirewall.workshop.aws/)
  * [AWS Networking Workshop](https://networking.workshop.aws/)
  * [Access Delegation](https://identity-round-robin.awssecworkshops.com/delegation/)
  * [Amazon VPC Endpoint Workshop](https://www.vpcendpointworkshop.com/)
  * [Build a Vulnerability Management Program Using AWS for AWS](https://vul-mgmt-program.awssecworkshops.com/)
  * [Data Discovery and Classification with Amazon Macie](https://data-discovery-and-classification.workshop.aws/)
  * [Data Protection](https://data-protection.awssecworkshops.com/)
  * [DevSecOps - Integrating security into your pipeline](https://devops.awssecworkshops.com/)
  * [Disaster Recovery on AWS](https://disaster-recovery.workshop.aws/)
  * [Finding and addressing Network Misconfigurations on AWS](https://validating-network-reachability.awssecworkshops.com/)
  * [Firewall Manager Service - WAF Policy](https://introduction-firewall-manager.workshop.aws/)
  * [Getting Hands on with Amazon GuardDuty](https://hands-on-guardduty.awssecworkshops.com/)
  * [Hands on Network Firewall Workshop](https://hands-on-network-firewall.workshop.aws/)
  * [Implementing DDoS Resiliency](https://ddos-protection-best-practices.workshop.aws/)
  * [Infrastructure Identity on AWS](https://idm-infrastructure.awssecworkshops.com/)
  * [Integrating security into your container pipeline](https://container-devsecops.awssecworkshops.com/)
  * [Integration, Prioritization, and Response with AWS Security Hub](https://pages.awscloud.com/Integration-Prioritization-and-Response-with-AWS-Security-Hub_2022_VW_s38e03-SID_OD)
  * [Introduction to WAF](https://introduction-to-waf.workshop.aws/)
  * [Permission boundaries: how to delegate permissions on AWS](https://identity-round-robin.awssecworkshops.com/permission-boundaries-advanced/)
  * [Protecting workloads on AWS from the instance to the edge](https://protecting-workloads.awssecworkshops.com/workshop/)
  * [Scaling threat detection and response on AWS](https://scaling-threat-detection.awssecworkshops.com/)
  * [Serverless Identity](https://identity-round-robin.awssecworkshops.com/serverless/)
* [PagerDuty Training Lab](https://sudo.pagerduty.com)
  * [PagerDuty Training GitHub](https://github.com/PagerDuty/security-training)
  * [PagerDuty Training for Engineers](https://sudo.pagerduty.com/for_engineers/)
  * [PagerDuty Training for Everyone: Part 1](https://sudo.pagerduty.com/for_everyone/)
  * [PagerDuty Training for Everyone: Part 2](https://sudo.pagerduty.com/for_everyone_part_ii/)
### Podcasts
* [Azure DevOps Podcast](http://azuredevopspodcast.clear-measure.com)
* [Cloud Security Podcast by Google](https://cloud.withgoogle.com/cloudsecurity/podcast/)
* [Security Now](https://twit.tv/shows/security-now)
### Vulnerable By Design
* [CloudGoat by Rhino Security Labs](https://github.com/RhinoSecurityLabs/cloudgoat)
* [ServerlessGoat by OWASP](https://github.com/OWASP/Serverless-Goat)
* [WrongSecrets by OWASP](https://github.com/commjoen/wrongsecrets)
## Certifications
* Cloud Vendors
  * [AWS Certified Security Specialty](https://aws.amazon.com/certification/certified-security-specialty/)
  * [Azure Security Engineer Associate](https://docs.microsoft.com/en-us/learn/certifications/azure-security-engineer/)
  * [Google Professional Cloud Security Engineer](https://cloud.google.com/certification/cloud-security-engineer)
  * [Oracle Cloud Platform Identity and Security Management](https://education.oracle.com/oracle-cloud-platform-identity-and-security-management-2020-certified-specialist/trackp_OCPISM2020CA)
* ISC<sup>2</sup> - International Information System Security Certification Consortium
  * [CCSP - Certified Cloud Security Professional](https://www.isc2.org/Certifications/CCSP)
* CSA - Cloud Security Alliance
  * [CCSK - Certificate of Cloud Security Knowledge](https://cloudsecurityalliance.org/education/ccsk/)
  * [CCAK - Certificate of Cloud Auditing Knowledge](https://cloudsecurityalliance.org/education/ccak/)
## Projects
### Alerting
* [411 by Etsy](https://github.com/etsy/411)
* [ElastAlert by Yelp](https://github.com/Yelp/elastalert)
* [StreamAlert by Airbnb](https://github.com/airbnb/streamalert)
### Automated Security Assessment
* [Prowler](https://github.com/prowler-cloud/prowler)
* [CloudFox](https://github.com/BishopFox/CloudFox)
* [SkyArk](https://github.com/cyberark/SkyArk)
* [Pacu](https://github.com/RhinoSecurityLabs/pacu)
* [Bucket Finder](https://digi.ninja/projects/bucket_finder.php)
* [Boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
* [Principal Mapper](https://github.com/nccgroup/PMapper)
* [ScoutSuite](https://github.com/nccgroup/ScoutSuite/wiki)
* [s3_objects_check](https://github.com/nccgroup/s3_objects_check)
* [cloudsplaining](https://github.com/salesforce/cloudsplaining)
* [weirdAAL](https://github.com/carnal0wnage/weirdAAL/wiki)
* [cloudmapper](https://github.com/duo-labs/cloudmapper)
* [NetSPI/AWS_Consoler](https://github.com/NetSPI/aws_consoler)
### Benchmarking
* [AWS Security Benchmark](https://github.com/awslabs/aws-security-benchmark)
### Data Loss Prevention
* [Git Secrets by AWS Labs](https://github.com/awslabs/git-secrets)
### Firewall Management
* globaldatanet
  * [AWS Firewall Factory](https://github.com/globaldatanet/aws-firewall-factory)
### Identity and Access Management
* AWS Labs
  * [AWS IAM Generator](https://github.com/awslabs/aws-iam-generator)
* Duo Labs
  * [Parliament](https://github.com/duo-labs/parliament)
  * [CloudTracker](https://github.com/duo-labs/cloudtracker)
* Netflix
  * [Aardvark](https://github.com/Netflix-Skunkworks/aardvark)
  * [ConsoleMe](https://github.com/Netflix/consoleme)
  * [PolicyUniverse](https://github.com/Netflix-Skunkworks/policyuniverse)
  * [Repokid](https://github.com/Netflix/Repokid)
* Pinterest
  * [Knox](https://github.com/pinterest/knox)
* Salesforce
  * [Policy Sentry](https://github.com/salesforce/policy_sentry/)
  * [CloudSplaining](https://github.com/salesforce/cloudsplaining)
  * [AWS-AllowLister](https://github.com/salesforce/aws-allowlister)
  * [Terraform for Policy Guru](https://github.com/salesforce/terraform-provider-policyguru)
* welldone.cloud
  * [aws-lint-iam-policies](https://github.com/welldone-cloud/aws-lint-iam-policies)
* Misc
  * [AWS Missing Tools by CloudAvail](https://github.com/cloudavail/aws-missing-tools)
  * [Awesome IAM List](https://github.com/kdeldycke/awesome-iam)
  * [Enumerate IAM by Andres Riancho](https://github.com/andresriancho/enumerate-iam)
  * [Kubernetes AWS IAM Authenticator by Kubernetes SIG](https://github.com/kubernetes-sigs/aws-iam-authenticator)
### Incident Response
* AWS
  * [AWS Incident Response Playbooks by AWS Samples](https://github.com/aws-samples/aws-incident-response-playbooks)
  * [AWS Security Hub Automated Response and Remediation](https://github.com/awslabs/aws-security-hub-automated-response-and-remediation)
* Netflix
  * [Dispatch by Netflix](https://github.com/Netflix/dispatch)
* PagerDuty
  * [PagerDuty Automated Remediation Docs](https://github.com/PagerDuty/automated-remediation-docs)
  * [PagerDuty Business Response Docs](https://github.com/PagerDuty/business-response-docs)
  * [PagerDuty DevSecOps Docs](https://github.com/PagerDuty/devsecops-docs)
  * [PagerDuty Full Case Ownership Docs](https://github.com/PagerDuty/full-case-ownership-docs)
  * [PagerDuty Full Service Ownership Docs](https://github.com/PagerDuty/full-service-ownership-docs)
  * [PagerDuty Going OnCall Docs](https://github.com/PagerDuty/goingoncall-docs)
  * [PagerDuty Incident Response Docs](https://github.com/PagerDuty/incident-response-docs)
  * [PagerDuty Operational Review Docs](https://github.com/PagerDuty/operational-review-docs)
  * [PagerDuty PostMortem Docs](https://github.com/PagerDuty/postmortem-docs)
  * [PagerDuty Retrospectives Docs](https://github.com/PagerDuty/retrospectives-docs)
  * [PagerDuty Stakeholder Communication Docs](https://github.com/PagerDuty/stakeholder-comms-docs)
* Velocidex
  * [Velociraptor](https://github.com/Velocidex/velociraptor) 
### Spring
* [Spring Cloud Security](https://github.com/dschadow/CloudSecurity)
### Threat modeling
* [ThreatModel for Amazon S3](https://github.com/trustoncloud/threatmodel-for-aws-s3) - Library of all the attack scenarios on Amazon S3 and how to mitigate them, following a risk-based approach
## Examples
### Ex. Automated Security Assessment
* [AWS Config Rules Repository](https://github.com/awslabs/aws-config-rules)
* [AWS Inspector Agent Autodeploy](https://github.com/awslabs/amazon-inspector-agent-autodeploy)
* [AWS Inspector Auto Remediation](https://github.com/awslabs/amazon-inspector-auto-remediate)
* [AWS Inspector Lambda Finding Processor](https://github.com/awslabs/amazon-inspector-finding-forwarder)
### Ex. Identity and Access Management
* [Amazon Cognito Streams connector for Amazon Redshift](https://github.com/awslabs/amazon-cognito-streams-sample)
### Ex. Logging
* [AWS Centralized Logging](https://github.com/awslabs/aws-centralized-logging)
* [AWS Config Snapshots to ElasticSearch](https://github.com/awslabs/aws-config-to-elasticsearch)
* [AWS CloudWatch Events Monitor Security Groups](https://github.com/awslabs/cwe-monitor-secgrp)
### Ex. Web Application Firewall
* [AWS WAF Sample](https://github.com/awslabs/aws-waf-sample)
* [AWS WAF Security Automations](https://github.com/awslabs/aws-waf-security-automations)
## Misc
* Other Awesome Lists
  * [Awesome Cloud Cost Control](https://github.com/Funkmyster/awesome-cloud-cost-control)
  * [Awesome Cloud Native Security](https://github.com/brant-ruan/awesome-cloud-native-security)
  * [Awesome Cloud Security](https://github.com/Funkmyster/awesome-cloud-security)
  * [Awesome IAM List](https://github.com/kdeldycke/awesome-iam)
  * [Awesome Incident Response List](https://github.com/meirwah/awesome-incident-response)
  * [Awesome Shodan Queries](https://github.com/jakejarvis/awesome-shodan-queries)


