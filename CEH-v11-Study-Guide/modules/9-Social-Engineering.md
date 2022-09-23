# Social Engineering

> ⚡︎ **This chapter has [practical labs](https://github.com/Samsar4/Ethical-Hacking-Labs/tree/master/8-Social-Engineering)**

*Social Engineering is the art of manipulating a person or group into providing information or a service they would otherwise not have given.*

## Phases
1. 🔍 **Research target company** 
    - Dumpster dive, visit websites, tour the company, etc
2. 🎯 **Select the victim** 
    - Identify frustrated employee or other target
3. 💬 **Build a relationship** 
    - Develop relationship with target employee
4. 💰 **Exploit the relationship** 
    - Collect sensitive information and current technologies

## Principles
1. **Authority**
	* Impersonate or imply a position of authority
2. **Intimidation**
	* Frighten by threat
3. **Consensus / Social proof**
	* To convince of a general group agreement
4. **Scarcity**
	* The situation will not be this way for long
5. **Urgency**
	* Works alongside scarcity / act quickly, don't think
6. **Familiarity**
	* To imply a closer relationship
7. **Trust**
	* To assure reliance on their honesty and integrity

## **Behaviors**
  - **Human nature/Trust** - trusting others
  - **Ignorance** of social engineering efforts
  - **Fear** of consequences of not providing the information
  - **Greed** - promised gain for providing requested information
  - A sense of **moral obligation**

## **Companies Common Risks:**
- **Insufficient training**
- **Lack of controls**
    - Technical
        - e.g: Firewall rule, ACL rules, patch management (...)
    - Administrative
        - e.g: Mandatory Vacations, Job Rotation, Separation of Duties (...)
    - Physical
        - e.g: Proper Lighting, Cameras, Guards, Mantraps (...)
- **Size of the Company Matters**
- **Lack of Policies**
    - Promiscuous Policy
    - Permisive Policy
    - Prudent Policy
    - Paranoid Policy

## <u>Social Engineering Attacks:</u>

## Human-Based Attacks 👥

- **Dumpster Diving** - Looking for sensitive information in the trash
  - Shredded papers can sometimes indicate sensitive info

- **Impersonation** - Pretending to be someone you're not
  - Can be anything from a help desk person up to an authoritative figure (FBI agent)
  - Posing as a tech support professional can really quickly gain trust with a person

- **Shoulder Surfing** - Looking over someone's shoulder to get info
  - Can be done long distance with binoculars, etc.

- **Eavesdropping** - Listening in on conversations about sensitive information

- **Tailgating** - Attacker walks in behind someone who has a valid badge. (e.g: Holding boxes or simply by following without getting notice)

- **Piggybacking** - Attacker pretends they lost their badge and asks someone to hold the door

- **RFID Identity Theft** (RFID skimming) - Stealing an RFID card signature with a specialized device

- **Reverse Social Engineering** - Getting someone to call you and give information
  - Often happens with tech support - an email is sent to user stating they need them to call back (due to technical issue) and the user calls back
  - Can also be combined with a DoS attack to cause a problem that the user would need to call about
  - Always be pleasant - it gets more information

- **Insider Attack** - An attack from an employee, generally disgruntled
  - Sometimes subclassified (negligent insider, professional insider)

## Computer-Based Attacks 💻
*Can begin with sites like Facebook where information about a person is available; For instance - if you know Bob is working on a project, an email crafted to him about that project would seem quite normal if you spoof it from a person on his project.*

- **Phishing** - crafting an email that appears legitimate but contains links to fake websites or to download malicious content.

  - **Ways to Avoid Phishing**
    - Beware unknown, unexpected or suspicious originators
    - Beware of who the email is addressed to
    - Verify phone numbers
    - Beware bad spelling or grammar
    - Always check links

- **Spear Phishing** - Targeting a person or a group with a phishing attack.
  - Can be more useful because attack can be targeted

- **Whaling** - Going after **CEOs** or other **C-level executives**.

- **Pharming** - Make a user's traffic redirects to a clone website; may use DNS poisoning.

- **Spamming** - Sending spam over instant message.

- **Fake Antivirus** - Very prevalent attack; pretends to be an anti-virus but is a malicious tool.

### **Tools**
- **SET (Social Engineering Toolkit)** - Pentest tool design to perform advanced attacks against human by exploiting their behavior.

- **PhishTank** -  For phishing detection

- **Wifiphisher** - Automated phishing attacks against Wi-Fi networks in order to obtain credentials or inject malware.

- **SPF SpeedPhish framework** - Quick recon and deployment of simple social eng. exercises

## <u>Mobile-Based Attacks</u>

- **ZitMo** (ZeuS-in-the-Mobile) - banking malware that was ported to Android
- SMS messages can be sent to request premium services
- **Attacks**
  - Publishing malicious apps
  - Repackaging legitimate apps
  - Fake security applications
  - SMS (**smishing**)

## <u>Physical Security Basics</u>

- **Physical measures** - everything you can touch, taste, smell or get shocked by
  - Includes things like air quality, power concerns, humidity-control systems
- **Technical measures** - smartcards and biometrics
- **Operational measures** - policies and procedures you set up to enforce a security-minded operation
- **Access controls** - physical measures designed to prevent access to controlled areas
  - **Biometrics** - measures taken for authentication that come from the "something you are" concept
    - **False rejection rate** (FRR) - when a biometric rejects a valid user
    - **False acceptance rate** (FAR) - when a biometric accepts an invalid user
    - **Crossover error rate** (CER) - combination of the two; determines how good a system is
- Even though hackers normally don't worry about environmental disasters, this is something to think of from a pen test standpoint (hurricanes, tornadoes, floods, etc.)

## Prevention
- Separation of duties
- Rotation of duties
- Controlled Access
    - Least privilege
- Logging & Auditing
- Policies 


