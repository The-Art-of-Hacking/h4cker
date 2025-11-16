# Penetration Testing and Wireless Adapters
As you learned either in one of my books, courses, or in the Internet, there are many challenges with different wireless adapters, Linux, and wireless penetration testing tools. This is a fact especially when trying to perform promiscuous monitoring and injecting packets into the wireless network.

The following are some of the most popular wireless adapters used by penetration testers (ethical hackers) in the industry.

**Note**: If you know of others and have some success stories, please feel free to contribute by requesting a pull request or by opening a GitHub issue.

## Good Resources of Field Tested Wireless Adapters

- [Select a Field-Tested Kali Linux Compatible Wireless Adapter](https://null-byte.wonderhowto.com/how-to/select-field-tested-kali-linux-compatible-wireless-adapter-0180076/)
- [Best Wireless Network Adapter for Wi-Fi ](https://null-byte.wonderhowto.com/how-to/buy-best-wireless-network-adapter-for-wi-fi-hacking-2018-0178550/)

## Additional Notes Based on My Personal Testing


### Atheros (AR5XXX, AR9XXX)
Atheros chipsets have been used by many pen testers in the industry because the ability to perform well with many different systems and because it is open source. The main challenge with these drivers is that many laptops have migrated from PCMCIA bus and support for external Atheros-based cards is pretty limited.

### Realtek (RTL8187)
The RTL8187 driver is used in many Alfa adapters (USB adapters). The RTL8187 driver is supported by the Linux kernel for years and has been the choice for many pen testers out there. The main challenge with this driver is the lack of 802.11 a, n, and ac support. It can be used for injecting packets into the wireless network and it works with MAC OS X.

### Intel Pro Wireless (iwlwifi)
Many vendors out there use Intel 802.11 chipsets in their laptops and desktop systems in the PCIe bus.

**Note:** Latest versions of the Intel chipsets are supported by the `iwlwifi` or the `iwlagn` Linux drivers and supported by recent kernels.

### The Alfa External Wireless Adapters
The Alfa adapters have been used by many pen testers in the industry for years.

#### The original Alfa AWUS306H
This is the legacy model and basically obsolete.

#### The Alfa AWUS036NEH
Is the newer version of the AWUS306H and provides support for 802.11n and it is smaller than its predecessor. One of the main challenges out there is that it is not supported by MAC OS X with KisMAC. However, many people use them in laptops or desktop machines using Kali Linux.

#### The Alfa Atheros AR9271 AWUS036NHA
Compatible with  802.11b, 802.11g or 802.11n using 2.4 GHZ wavelength.

#### The Alfa AWUS051NH
It's basically the same as the AWUS036NEH, but it adds support for 5 GHz. It is also not supported by MAC OS X.

#### Panda PAU05
The Panda PAU05 is a 2.4 GHz wireless N adapter that uses the Ralink RT3070 Chipset.

#### TP-Link TL-WN722N (100mW)
Very cheap and compatible with Kali Linux. It is not perfect for packet injection.

#### TP-Link N150 Wireless High Gain USB Adapter (TL-WN722N)
The TP-LINK TL-WN722N uses the Atheros AR9271 Chipset and is a wireless N adapter. Newer versions may not use the same chipset and you may run into problems with Kali Linux.

## WiFi Pineapple 
[Hak5's Wifi Pineapple](https://shop.hak5.org/products/wifi-pineapple) is a very comprehensive framework (hardware and software) that can be used to easily launch several WiFi attacks.
