# Building Your Own Cybersecurity Lab and Cyber Range

The following are some tips and instructions on how you can build your own lab for penetration testing and to practice different defensive techniques helpful for incident response and digital forensics.

## Pen Testing Linux Distributions

While most of the penetration testing tools can be downloaded in isolation and installed in many different operating systems, several popular security-related Linux distributions package hundreds of tools. These distributions make it easy for you to get started and not having to worry about many dependencies, libraries, and compatibility issues you may encounter. The following are the three most popular Linux distributions for ethical hacking (penetration testing): 

- [Kali Linux](https://www.kali.org): probably the most popular distribution of the three. This distribution is primarily supported and maintained by Offensive Security and can be downloaded from https://www.kali.org. You can easily install it in bare-metal systems, virtual machines, and even in devices like the Raspberry Pi, Chromebooks, and many others.
Note: The folks at Offensive Security have created a free training and book that guides you how to install it in your system. Those resources can be accessed at: https://kali.training 

- [Parrot](https://www.parrotsec.org): is another popular Linux distribution used by many pen testers and security researchers. You can also install it in bare-metal and in virtual machines. You can download Parrot from https://www.parrotsec.org

- [BlackArch Linux](https://blackarch.org): this distribution comes with over 2300 different tools and packages and it is also gaining popularity. You can download BlackArch Linux from: https://blackarch.org

- [The PenTesters Framework (PTF)](https://github.com/trustedsec/ptf): a Python script designed for Debian/Ubuntu/ArchLinux based distributions to create a similar and familiar distribution for Penetration Testing. Created by David Kennedy and maintained by the community.

- [Pentoo Linux](https://www.pentoo.ch/):Pentoo is a Live CD and Live USB designed for penetration testing and security assessment. Pentoo Linux is a distribution that is designed to be free of the systemd init system. Pentoo is based on Gentoo Linux and is specifically tailored for penetration testing and security auditing. It focuses on providing a lightweight and flexible environment for security professionals and enthusiasts. One of the defining characteristics of Pentoo Linux is its avoidance of systemd as the init system. Instead, Pentoo uses the OpenRC (Open Runlevel Configuration) init system, which is known for its simplicity and ease of customization. OpenRC is an alternative init system that provides similar functionality to systemd but with a different approach. By using OpenRC, Pentoo Linux aims to offer a systemd-free environment while maintaining its focus on security testing and auditing tools. 

- [PwnMachine by YesWeHack](https://github.com/yeswehack/pwn-machine): a self hosting solution based on docker aiming to provide an easy to use pwning station for bug hunters. The basic install include a web interface, a DNS server and a reverse proxy.

## Privacy Oriented Distributions

- [Tails](https://tails.boum.org/)
- [Whonix](https://www.whonix.org/)
- [Qubes OS](https://www.qubes-os.org/)
- [Ubuntu Privacy Remix](http://www.privacyremix.org/)
- [Subgraph OS](https://subgraph.com/sgos/)

## WebSploit Labs: A Convenient, Simple, Yet Powerful Learning Environment

[WebSploit Labs](https://websploit.org/) is a learning environment created by [Omar Santos](https://omarsantos.io) for different Cybersecurity Ethical Hacking ( Penetration Testing) training sessions delivered at [DEFCON](https://www.wallofsheep.com/blogs/news/packet-hacking-village-workshops-at-def-con-26-finalized), [DEF CON Red Team Village](https://redteamvillage.io), [O'Reilly Live Training (foremely known as Safari)](https://learning.oreilly.com/search/?query=omar%20santos&extended_publisher_data=true&highlight=true&include_assessments=false&include_case_studies=true&include_courses=true&include_playlists=true&include_collections=true&include_notebooks=true&is_academic_institution_account=false&source=user&formats=live%20online%20training&sort=relevance&facet_json=true&page=0&include_facets=false&include_scenarios=true&include_sandboxes=true&json_facets=true), and many other conferences and forums. 

The purpose of this VM is to have a lightweight (single VM) with a few web application penetration testing tools, as well as vulnerable applications.

## Vulnerable Servers and Applications

There are several intentionally vulnerable applications and virtual machines that you can deploy in a lab (safe) environment to practice your skills. You can also run some of them in Docker containers. 

Go to the [Vulnerable Servers Section](https://github.com/The-Art-of-Hacking/art-of-hacking/tree/master/vulnerable_servers) of this GitHub repository to obtain a list of dozens of vulnerable applications and VMs that can be used to practice your skills.


## Cloud-Based Cyber Ranges
- [Awesome Cloud Labs](https://github.com/iknowjason/Awesome-CloudSec-Labs): A list of free cloud native security learning labs. Includes CTF, self-hosted workshops, guided vulnerability labs, and research labs.
- [PurpleCloud](https://github.com/iknowjason/PurpleCloud):  Cyber Range environment created by [Jason Ostrom](https://twitter.com/securitypuck) using Active Directory and automated templates for building your own Pentest/Red Team/Cyber Range in the Azure cloud!
- [CyberRange by SECDEVOPS@CUSE](https://github.com/secdevops-cuse/CyberRange): AWS-based Cyber Range.
- [Create A VPS On Google Cloud Platform Or Digital Ocean Easily With The Docker For Pentest](https://github.com/aaaguirrep/offensive-docker-vps)
- [How to Build a Cloud Hacking Lab](https://www.youtube.com/watch?v=4s_3oNwqImo)
- [Splunk Attack Range](https://github.com/splunk/attack_range)

## Additional Resources
[This repository from @reswob10](https://github.com/reswob10/HomeLabResources) is an amazing resource. It includes references of blogs and videos that explain different lab setup, tools, and automation.
