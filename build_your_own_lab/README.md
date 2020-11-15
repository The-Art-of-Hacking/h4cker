# Building Your Own Penetration Testing Lab

The following are some tips and instructions on how you can build your own lab for penetration testing and to practice different defensive techniques helpful for incident response and digital forensics.

## Pen Testing Linux Distributions

While most of the penetration testing tools can be downloaded in isolation and installed in many different operating systems, several popular security-related Linux distributions package hundreds of tools. These distributions make it easy for you to get started and not having to worry about many dependencies, libraries, and compatibility issues you may encounter. The following are the three most popular Linux distributions for ethical hacking (penetration testing): 

- [Kali Linux](https://www.kali.org): probably the most popular distribution of the three. This distribution is primarily supported and maintained by Offensive Security and can be downloaded from https://www.kali.org. You can easily install it in bare-metal systems, virtual machines, and even in devices like the Raspberry Pi, Chromebooks, and many others.
Note: The folks at Offensive Security have created a free training and book that guides you how to install it in your system. Those resources can be accessed at: https://kali.training 

- [Parrot](https://www.parrotsec.org): is another popular Linux distribution used by many pen testers and security researchers. You can also install it in bare-metal and in virtual machines. You can download Parrot from https://www.parrotsec.org

- [BlackArch Linux](https://blackarch.org): this distribution comes with over 2300 different tools and packages and it is also gaining popularity. You can download BlackArch Linux from: https://blackarch.org

- [The PenTesters Framework (PTF)](https://github.com/trustedsec/ptf): a Python script designed for Debian/Ubuntu/ArchLinux based distributions to create a similar and familiar distribution for Penetration Testing. Created by David Kennedy and maintained by the community.

- [Offensive Docker](https://github.com/aaaguirrep/pentest): Image with the more used tools to create a pentest environment easily and quickly.

## Vulnerable Servers and Applications

There are several intentionally vulnerable applications and virtual machines that you can deploy in a lab (safe) environment to practice your skills. You can also run some of them in Docker containers. 

Go to the [Vulnerable Servers Section](https://github.com/The-Art-of-Hacking/art-of-hacking/tree/master/vulnerable_servers) of this GitHub repository to obtain a list of dozens of vulnerable applications and VMs that can be used to practice your skills.


## WebSploit Labs

[WebSploit Labs](https://websploit.org/) is a learning environment created by [Omar Santos](https://omarsantos.io) for different Cybersecurity Ethical Hacking ( Penetration Testing) training sessions delivered at [DEFCON](https://www.wallofsheep.com/blogs/news/packet-hacking-village-workshops-at-def-con-26-finalized), [DEF CON Red Team Village](https://redteamvillage.io), [O'Reilly Live Training (foremely known as Safari)](https://learning.oreilly.com/search/?query=omar%20santos&extended_publisher_data=true&highlight=true&include_assessments=false&include_case_studies=true&include_courses=true&include_playlists=true&include_collections=true&include_notebooks=true&is_academic_institution_account=false&source=user&formats=live%20online%20training&sort=relevance&facet_json=true&page=0&include_facets=false&include_scenarios=true&include_sandboxes=true&json_facets=true), and many other conferences and forums. 

The purpose of this VM is to have a lightweight (single VM) with a few web application penetration testing tools, as well as vulnerable applications.


## Cloud-Based Cyber Ranges
- [PurpleCloud](https://github.com/iknowjason/PurpleCloud):  Cyber Range environment created by [Jason Ostrom](https://twitter.com/securitypuck) using Active Directory and automated templates for building your own Pentest/Red Team/Cyber Range in the Azure cloud!
- [CyberRange by SECDEVOPS@CUSE](https://github.com/secdevops-cuse/CyberRange): AWS-based Cyber Range.
- [Create A VPS On Google Cloud Platform Or Digital Ocean Easily With The Docker For Pentest](https://github.com/aaaguirrep/offensive-docker-vps)

