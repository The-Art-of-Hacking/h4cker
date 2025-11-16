# Wireless Attack Resources
The following are several resources describing different wireless attacks, vulnerabilities, and mitigations. I also included several tips on how to build your own wireless hacking lab.

## How to Build Your Own Wireless Hacking Lab
- [Penetration Testing and Wireless Adapters](https://github.com/The-Art-of-Hacking/h4cker/blob/master/wireless-resources/wireless_adapters.md): As you learned either in one of my books, courses, or in the Internet, there are many challenges with different wireless adapters, Linux, and wireless penetration testing tools. This is a fact especially when trying to perform promiscuous monitoring and injecting packets into the wireless network. [These are my notes](https://github.com/The-Art-of-Hacking/h4cker/blob/master/wireless-resources/wireless_adapters.md) of some of the most popular wireless adapters used by penetration testers (ethical hackers) in the industry.
- [Build your WiFi environment with Linux Kernel Modules](https://github.com/The-Art-of-Hacking/h4cker/blob/master/wireless-resources/virtual_adapters.md): You can use mac80211_hwsim is a software simulator of 802.11 radio(s) for mac80211 in Kali Linux, Parrot Security and other Linux distributions. [In this section](https://github.com/The-Art-of-Hacking/h4cker/blob/master/wireless-resources/virtual_adapters.md) I demonstrate how to use the mac80211_hwsim Linux kernel module to create your own wireless learning lab without the need of buying any adapters.
- [Additional Tools and Other Resources](https://github.com/The-Art-of-Hacking/h4cker/blob/master/wireless-resources/tools_and_online_resources.md): A collection of additional tools and learning resources.

## Attacks Against WPA3
Mathy Vanhoef discovered several vulnerabilties that affect the WPA3 WiFi protocol. There are two categories in these attacks. The first category consists of downgrade attacks against WPA3-capable devices, and the second category consists of weaknesses in the Dragonfly handshake of WPA3, which in the Wi-Fi standard is better known as the Simultaneous Authentication of Equals (SAE) handshake.

### Dragonfly Handshake and other WPA3 Attacks
The following are several references to these attacks:
- [WPA3 Dragonblood](https://wpa3.mathyvanhoef.com)
- [CERT ID #VU871675](https://www.kb.cert.org/vuls/id/VU871675): Downgrade attack against WPA3-Transtition mode leading to dictionary attacks.
- [CERT ID #VU871675](https://www.kb.cert.org/vuls/id/VU871675): Security group downgrade attack against WPA3's Dragonfly handshake.
- [CVE-2019-9494](https://nvd.nist.gov/vuln/detail/CVE-2019-9494): Timing-based side-channel attack against WPA3's Dragonfly handshake and Cache-based side-channel attack against WPA3's Dragonfly handshake.
- [CERT ID #VU871675](https://www.kb.cert.org/vuls/id/VU871675): Resource consumption attack (i.e. denial of service) against WPA3's Dragonfly handshake.
- [CERT ID #VU871675](https://kb.cert.org/vuls/id/871675/): Overview of attacks specific to hostapd and wpa_supplicant (does not cover other implementations).
- [CVE-2019-9495](https://nvd.nist.gov/vuln/detail/CVE-2019-9495): Cache-based side-channel attack against the EAP-pwd implementation of hostapd and wpa_supplicant.
- [CVE-2019-9497](https://nvd.nist.gov/vuln/detail/CVE-2019-9497): Reflection attack against the EAP-pwd implementation of hostapd and wpa_supplicant.
- [CVE-2019-9498](https://nvd.nist.gov/vuln/detail/CVE-2019-9498): Invalid curve attack against the EAP-pwd server of hostapd resulting in authentication bypass.
- [CVE-2019-9499](https://nvd.nist.gov/vuln/detail/CVE-2019-9499): Invalid curve attack against the EAP-pwd client of wpa_supplicant resulting in server impersonation.
- [CVE-2019-11234](https://nvd.nist.gov/vuln/detail/CVE-2019-11234): Reflection attack against the EAP-pwd implementation of FreeRADIUS.
- [CVE-2019-11235](https://nvd.nist.gov/vuln/detail/CVE-2019-11235): Invalid curve attack against the EAP-pwd server of FreeRADIUS resulting in authentication bypass.

### FragAttacks (fragmentation and aggregation attacks)
[FragAttacks](https://www.fragattacks.com/) is a series of vulnerabilities also found by Mathy Vanhoef. An adversary that is within range of a victim's Wi-Fi network can abuse these vulnerabilities to steal user information or attack devices. Three of the discovered vulnerabilities are design flaws in the Wi-Fi standard and therefore affect most devices.

#### Design Flaws

- **CVE-2020-24588: Accepting non-SPP A-MSDU frames**: The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent Privacy (WEP) doesn't require that the A-MSDU flag in the plaintext QoS header field is authenticated. Against devices that support receiving non-SPP A-MSDU frames, which is mandatory as part of 802.11n, an adversary can abuse this to inject arbitrary network packets.

- **CVE-2020-24587: Reassembling fragments encrypted under different keys**: The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent Privacy (WEP) doesn't require that all fragments of a frame are encrypted under the same key. An adversary can abuse this to exfiltrate selected fragments when another device sends fragmented frames and the WEP, CCMP, or GCMP encryption key is periodically renewed.

- **CVE-2020-24586: Not clearing fragments from memory when (re)connecting to a network:** The 802.11 standard that underpins Wi-Fi Protected Access (WPA, WPA2, and WPA3) and Wired Equivalent Privacy (WEP) doesn't require that received fragments must be cleared from memory after (re)connecting to a network. Under the right circumstances, when another device sends fragmented frames encrypted using WEP, CCMP, or GCMP, this can be abused to inject arbitrary network packets and/or exfiltrate user data.

## Implementation flaws allowing trivial packet injection

- **CVE-2020-26145: Accepting plaintext broadcast fragments as full frames (in an encrypted network)**: Vulnerable WEP, WPA, WPA2, or WPA3 implementations accept second (or subsequent) broadcast fragments even when sent in plaintext and process them as full unfragmented frames. An adversary can abuse this to inject arbitrary network packets independent of the network configuration.

- **CVE-2020-26144: Accepting plaintext A-MSDU frames that start with an RFC1042 header with EtherType EAPOL (in an encrypted network)**: Vulnerable Wi-Fi implementations accept plaintext A-MSDU frames as long as the first 8 bytes correspond to a valid RFC1042 (i.e., LLC/SNAP) header for EAPOL. An adversary can abuse this to inject arbitrary network packets independent of the network configuration.

- **CVE-2020-26140: Accepting plaintext data frames in a protected network**: Vulnerable WEP, WPA, WPA2, or WPA3 implementations accept plaintext frames in a protected Wi-Fi network. An adversary can abuse this to inject arbitrary data frames independent of the network configuration.

- **CVE-2020-26143: Accepting _fragmented_ plaintext data frames in a protected network**: Vulnerable WEP, WPA, WPA2, or WPA3 implementations accept fragmented plaintext frames in a protected Wi-Fi network. An adversary can abuse this to inject arbitrary data frames independent of the network configuration.

#### Other Implementation Vulnerabilities

- **CVE-2020-26139: Forwarding EAPOL frames even though the sender is not yet authenticated**: Vulnerable Access Points (APs) forward EAPOL frames to other clients even though the sender has not yet successfully authenticated to the AP. An adversary might be able to abuse this in projected Wi-Fi networks to launch denial-of-service attacks against connected clients, and this makes it easier to exploit other vulnerabilities in connected clients.

- **CVE-2020-26146: Reassembling encrypted fragments with non-consecutive packet numbers**: Vulnerable WPA, WPA2, or WPA3 implementations reassemble fragments with non-consecutive packet numbers. An adversary can abuse this to exfiltrate selected fragments. This vulnerability is exploitable when another device sends fragmented frames and the WEP, CCMP, or GCMP data-confidentiality protocol is used. Note that WEP is vulnerable to this attack by design.

- **CVE-2020-26147: Reassembling mixed encrypted/plaintext fragments**: Vulnerable WEP, WPA, WPA2, or WPA3 implementations reassemble fragments even though some of them were sent in plaintext. This vulnerability can be abused to inject packets and/or exfiltrate selected fragments when another device sends fragmented frames and the WEP, CCMP, or GCMP data-confidentiality protocol is used.

- **CVE-2020-26142: Processing fragmented frames as full frames**: Vulnerable WEP, WPA, WPA2, or WPA3 implementations treat fragmented frames as full frames. An adversary can abuse this to inject arbitrary network packets, independent of the network configuration.

- **CVE-2020-26141: Not verifying the TKIP MIC of fragmented frames**: Vulnerable Wi-Fi implementations do not verify the Message Integrity Check (authenticity) of fragmented TKIP frames. An adversary can abuse this to inject and possibly decrypt packets in WPA or WPA2 networks that support the TKIP data-confidentiality protocol.



