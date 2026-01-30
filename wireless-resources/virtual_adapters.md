# Using Kernel Modules to Simulate Wireless Adapters to Practice Pen Testing

You can use mac80211_hwsim is a software simulator of 802.11 radio(s) for mac80211 in Kali Linux and other penetration testing distributions like Parrot.

[mac80211_hwsim](https://wireless.wiki.kernel.org/en/users/drivers/mac80211_hwsim) kernel module has a parameter 'radios' that can be used to select how many radios are simulated (default 2). This allows configuration of both very simply setups (e.g., just a single access point and a station) or large scale tests (multiple access points with hundreds of stations).

The following site provides a description:
- https://wireless.wiki.kernel.org/en/users/drivers/mac80211_hwsim

## Starting the Kernel Module in Kali

In my Kali Linux box, I have only one active interface (eth0). 

```
root@kali:~# ip -brie a
lo               UNKNOWN        127.0.0.1/8 ::1/128
eth0             UP             172.16.217.170/24 fe80::20c:29ff:fe3c:82b0/64
```

I am starting the simulator kernel module with the `modprobe mac80211_hwsim` command:

```
root@kali:~# modprobe mac80211_hwsim radios=8
```

After starting the module, the wireless interfaces are shown:

```
root@kali:~# ip -brie a
lo               UNKNOWN        127.0.0.1/8 ::1/128
eth0             UP             172.16.217.170/24 fe80::20c:29ff:fe3c:82b0/64
wlan0            DOWN
wlan1            DOWN
hwsim0           DOWN
```

`modprobe mac80211_hwsim radios=8` loads the Linux [mac80211_hwsim kernel module](https://wireless.docs.kernel.org/en/latest/en/users/drivers/mac80211_hwsim.html) and tells it to create 8 simulated Wi‑Fi radios.

### Breaking it down

- `modprobe`  
  Loads a kernel module (and any dependencies) into the running kernel, using options you pass on the command line.

- `mac80211_hwsim`  
  This is a special testing/simulation driver that emulates IEEE 802.11 hardware for the mac80211 stack, so user‑space tools like `hostapd`, `wpa_supplicant`, `iw`, etc., see them as real Wi‑Fi devices. 

- `radios=8` (module parameter)  
  The module has a parameter called `radios` that specifies how many virtual radios to create when the module is inserted. 
  - Default is 2 if you omit it. 
  - With `radios=8`, the kernel will register 8 independent simulated PHYs, typically exposing interfaces like `wlan0` … `wlan7` (plus a global `hwsim0` monitor device). 

### Practical effect

After running `modprobe mac80211_hwsim radios=8`:

- You get 8 virtual Wi‑Fi radios you can see with `iw dev` or `iw phy`.
- Each can be configured independently (AP, STA, monitor, different channels, etc.), allowing you to build multi‑AP / multi‑STA test topologies entirely in software on a single host.


## Installing `hostapd`

You can then install `hostapd` to create a wireless access point and then use aircrack-ng to perform wireless assessments. `hostapd` is a user‑space daemon that turns a wireless interface into a Wi‑Fi access point and handles client authentication.



## Install and Configure hostapd

You can then install `hostapd`, as shown below:

```
root@kali:~# sudo apt install hostapd
Reading package lists... Done
Building dependency tree
Reading state information... Done
The following NEW packages will be installed:
  hostapd
0 upgraded, 1 newly installed, 0 to remove and 1748 not upgraded.
Need to get 608 kB of archives.
After this operation, 1,549 kB of additional disk space will be used.
Get:1 http://archive.linux.duke.edu/kalilinux/kali kali-rolling/main amd64 hostapd amd64 2:2.6-18 [608 kB]
Fetched 608 kB in 2s (301 kB/s)
Selecting previously unselected package hostapd.
(Reading database ... 353210 files and directories currently installed.)
Preparing to unpack .../hostapd_2%3a2.6-18_amd64.deb ...
Unpacking hostapd (2:2.6-18) ...
Setting up hostapd (2:2.6-18) ...
Created symlink /etc/systemd/system/hostapd.service → /dev/null.
update-rc.d: We have no instructions for the hostapd init script.
update-rc.d: It looks like a network service, we disable it.
Processing triggers for systemd (238-4) ...
Processing triggers for man-db (2.8.2-1) ...
Scanning processes...
Scanning candidates...
Scanning processor microcode...
Scanning linux images...

Running kernel seems to be up-to-date.

No services need to be restarted.

No containers need to be restarted.

User sessions running outdated binaries:
 root @ session #3: bash[1599]
root@kali:~# hostapd
hostapd v2.6
User space daemon for IEEE 802.11 AP management,
IEEE 802.1X/WPA/WPA2/EAP/RADIUS Authenticator
Copyright (c) 2002-2016, Jouni Malinen <j@w1.fi> and contributors

usage: hostapd [-hdBKtv] [-P <PID file>] [-e <entropy file>] \
         [-g <global ctrl_iface>] [-G <group>]\
         [-i <comma-separated list of interface names>]\
         <configuration file(s)>

options:
   -h   show this usage
   -d   show more debug messages (-dd for even more)
   -B   run daemon in the background
   -e   entropy file
   -g   global control interface path
   -G   group for control interfaces
   -P   PID file
   -K   include key data in debug messages
   -f   log output to debug file instead of stdout
   -T = record to Linux tracing in addition to logging
        (records all messages regardless of debug verbosity)
   -i   list of interface names to use
   -S   start all the interfaces synchronously
   -t   include timestamps in some debug messages
   -v   show hostapd version
root@kali:~#
```

**Note:** You can obtain the example of my `hostapd.conf` file [here](https://github.com/The-Art-of-Hacking/h4cker/blob/master/wireless-resources/hostapd.conf).

In my case, I ran into the following problem:

```
root@kali:# hostapd /etc/hostapd/hostapd.conf
Configuration file: /etc/hostapd/hostapd.conf
nl80211: Could not configure driver mode
nl80211: deinit ifname=wlan0 disabled_11b_rates=0
nl80211 driver initialization failed.
wlan0: interface state UNINITIALIZED->DISABLED
wlan0: AP-DISABLED
hostapd_free_hapd_data: Interface wlan0 wasn't started
```
I fixed it as follows:

```
root@kali:# sudo nmcli radio wifi off
root@kali:# sudo rfkill unblock wlan
root@kali:# sudo ifconfig wlan0 10.15.0.1/24 up
root@kali:# hostapd /etc/hostapd/hostapd.conf
Configuration file: /etc/hostapd/hostapd.conf
Using interface wlan0 with hwaddr 26:6f:2b:e1:48:d1 and ssid "corp-net"
wlan0: interface state UNINITIALIZED->ENABLED
wlan0: AP-ENABLED
```

## Running aircrack-ng

If you are not familiar with aircrack-ng, you can watch the video course at: https://h4cker.org/wireless

Let's start `airmon-ng` and then launch `airodump-ng` just to test our configuration:

```
root@kali:~# airmon-ng start wlan1

Found 3 processes that could cause trouble.
If airodump-ng, aireplay-ng or airtun-ng stops working after
a short period of time, you may want to run 'airmon-ng check kill'

  PID Name
  544 NetworkManager
  576 dhclient
  723 wpa_supplicant

PHY	Interface	Driver		Chipset

phy0	wlan0		mac80211_hwsim	Software simulator of 802.11 radio(s) for mac80211
phy1	wlan1		mac80211_hwsim	Software simulator of 802.11 radio(s) for mac80211

		(mac80211 monitor mode vif enabled for [phy1]wlan1 on [phy1]wlan1mon)
		(mac80211 station mode vif disabled for [phy1]wlan1)

root@kali:~#
```

Now, let's run airodump-ng:

```
root@kali:~# airodump-ng wlan1mon
```

You should see the corp-net SSID that is configured in the hostapd.conf file.

```
 CH 12 ][ Elapsed: 6 s ][ 2018-11-27 23:02

 BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID

 26:6F:2B:E1:48:D1  -29        5        0    0  11  54   WPA  TKIP   MGT  corp-net

 BSSID              STATION            PWR   Rate    Lost    Frames  Probe
```

## Installing DHCP server

Dnsmasq is going to act as our DNS and DHCP server, it can be installed with apt-get install dnsmasq. This is another super simple service with an easy to understand config file. Below is what I used, it defines a DHCP range, sets the router and DNS servers as 10.0.0.1 (options 3 and 6) and sets our upstream DNS server to one of OpenDNS's public DNS servers (server=208.67.222.222).

```
interface=wlan0
dhcp-range=10.0.0.10,10.0.0.100,8h
dhcp-option=3,10.0.0.1
dhcp-option=6,10.0.0.1
server=208.67.222.222
log-queries
log-dhcp
```
