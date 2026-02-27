# Internet of Things (IoT) Hacking Resources
The Internet of Things (IoT) Hacking Resources refer to an array of tools and frameworks used to ensure the security of IoT devices and networks.

## IoT Security Projects

- [GlowBarn](https://github.com/bad-antics/glowbarn-os) - Open-source Raspberry Pi-based smart agriculture IoT system with integrated security monitoring, sensor data collection, and anomaly detection for farm environments.

## Analysis Frameworks

- [EXPLIoT](https://gitlab.com/expliot_framework/expliot): This is a penetrating testing framework that is akin to Metasploit, but it specifically caters to Internet of Things (IoT) applications. 
- [FACT - The Firmware Analysis and Comparison Tool](https://fkie-cad.github.io/FACT_core/): A comprehensive static analysis tool that specializes in firmware extraction, plugin-facilitated analysis, and comparison between different firmware versions. To understand more, watch this [conference talk](https://passthesalt.ubicast.tv/videos/improving-your-firmware-security-analysis-process-with-fact/) discussing enhancements in the firmware security analysis process using FACT.
- [FwAnalyzer](https://github.com/cruise-automation/fwanalyzer): Designed to evaluate firmware security via customized rule-based analysis. It's an excellent complementary step in DevSecOps, analogous to Continuous Integration (CI) in function.
- [HAL – The Hardware Analyzer](https://github.com/emsec/hal): An all-encompassing reverse engineering tool that provides a manipulation framework for gate-level netlists. 
- [HomePWN](https://github.com/ElevenPaths/HomePWN): Consider it your Swiss Army Knife for penetration testing of IoT devices. 
- [IoTSecFuzz](https://gitlab.com/invuls/iot-projects/iotsecfuzz): This framework automates the security analysis of IoT layers, including hardware, software, and communication. 
- [Killerbee](https://github.com/riverloopsec/killerbee): An established framework for the testing and auditing of ZigBee and IEEE 802.15.4 networks. 
- [PRET](https://github.com/RUB-NDS/PRET): The go-to toolkit for printer exploitation. 
- [Routersploit](https://github.com/threat9/routersploit): A dedicated framework specifically designed to exploit embedded devices.

## Advanced Tools for Binary and Firmware Analysis

- [Binwalk](https://github.com/ReFirmLabs/binwalk): This powerful tool delves into binaries to identify "interesting" elements and also facilitates the extraction of arbitrary files.
- [emba](https://github.com/e-m-b-a/emba): Designed specifically to analyze the Linux-based firmware of embedded devices, emba provides a comprehensive framework for firmware scrutiny.
- [Firmadyne](https://github.com/firmadyne/firmadyne): This resource aims to emulate and conduct penetration tests on various firmwares, providing a simulation environment for security testing.
- [Firmwalker](https://github.com/craigz28/firmwalker): This tool specializes in exploring extracted firmware images, searching for relevant files and information.
- [Firmware Slap](https://github.com/ChrisTheCoolHut/Firmware_Slap): A unique tool for discovering vulnerabilities in firmware through the method of concolic analysis and function clustering.
- [Ghidra](https://ghidra-sre.org/): Ghidra is a comprehensive Software Reverse Engineering suite. It can manage arbitrary binaries when provided with the CPU architecture and endianness of the binary.
- [Radare2](https://github.com/radare/radare2): This is a versatile Software Reverse Engineering framework. Capable of handling popular formats and arbitrary binaries, it boasts an extensive command line toolkit.
- [Trommel](https://github.com/CERTCC/trommel): Trommel conducts a detailed search through extracted firmware images, hunting for relevant files and intriguing information.

## Tools for Firmware Extraction and Manipulation

- [FACT Extractor](https://github.com/fkie-cad/fact_extractor): This intelligent tool identifies container formats automatically and triggers the appropriate extraction tool, thereby streamlining the process.
- [Firmware Mod Kit](https://github.com/rampageX/firmware-mod-kit/wiki): This kit provides a range of extraction tools compatible with various container formats, offering a versatile solution for firmware modification.
- [The SRecord package](http://srecord.sourceforge.net/): This package encompasses a suite of tools for manipulating EPROM files. Its functionality includes the ability to convert numerous binary formats, providing an essential resource for binary file conversion and manipulation.
- [JTAGenum](https://github.com/cyphunk/JTAGenum) - Add JTAG capabilities to an Arduino.
- [OpenOCD](http://openocd.org/) - Free and Open On-Chip Debugging, In-System Programming and Boundary-Scan Testing.

## Misc Tools

- [Cotopaxi](https://github.com/Samsung/cotopaxi) - Set of tools for security testing of Internet of Things devices using specific network IoT protocols.
- [dumpflash](https://github.com/ohjeongwook/dumpflash) - Low-level NAND Flash dump and parsing utility.
- [flashrom](https://github.com/flashrom/flashrom) - Tool for detecting, reading, writing, verifying and erasing flash chips.
- [Samsung Firmware Magic](https://github.com/chrivers/samsung-firmware-magic) - Decrypt Samsung SSD firmware updates.

## Hardware Tools

- [Bus Blaster](http://dangerousprototypes.com/docs/Bus_Blaster) - Detects and interacts with hardware debug ports like [UART](https://en.wikipedia.org/wiki/Universal_asynchronous_receiver-transmitter) and [JTAG](https://en.wikipedia.org/wiki/JTAG).
- [Bus Pirate](http://dangerousprototypes.com/docs/Bus_Pirate) - Detects and interacts with hardware debug ports like UART and JTAG.
- [GreatFET One](https://www.adafruit.com/product/4234) - If you need an interface to an external chip, a logic analyzer, a debugger, or just a whole lot of pins to bit-bang, the versatile GreatFET One is the tool for you.
- [Shikra](https://int3.cc/products/the-shikra) - Detects and interacts with hardware debug ports like UART and JTAG. Among other protocols.
- [JTAGULATOR](http://www.grandideastudio.com/jtagulator/) - Detects JTAG Pinouts fast.
- [Saleae](https://www.saleae.com/) - Easy to use Logic Analyzer that support many protocols :euro:.
- [Ikalogic](https://www.ikalogic.com/pages/logic-analyzer-sp-series-sp209) - Alternative to Saleae logic analyzers :euro:.
- [HydraBus](https://hydrabus.com/hydrabus-1-0-specifications/) - Open source multi-tool hardware similar to the BusPirate but with NFC capabilities.
- [ChipWhisperer](https://newae.com/chipwhisperer/) - Detects Glitch/Side-channel attacks.
- [Glasgow](https://github.com/GlasgowEmbedded/Glasgow) - Tool for exploring and debugging different digital interfaces.
- [J-Link](https://www.segger.com/products/debug-probes/j-link/models/model-overview/) - J-Link offers USB powered JTAG debug probes for multiple different CPU cores :euro:.

## Bluetooth BLE Tools

- [UberTooth One](https://greatscottgadgets.com/ubertoothone/) - Open source 2.4 GHz wireless development platform suitable for Bluetooth experimentation.
- [Bluefruit LE Sniffer](https://www.adafruit.com/product/2269) - Easy to use Bluetooth Low Energy sniffer.

## ZigBee Tools

- [ApiMote](http://apimote.com) - ZigBee security research hardware for learning about and evaluating the security of IEEE 802.15.4/ZigBee systems. Killerbee compatible.
- Atmel RZUSBstick - Discontinued product. Lucky if you have one! - Tool for development, debugging and demonstration of a wide range of low power wireless applications including IEEE 802.15.4, 6LoWPAN, and ZigBee networks. Killerbee compatible.
- [Freakduino](https://freaklabsstore.com/index.php?main_page=product_info&cPath=22&products_id=219&zenid=fpmu2kuuk4abjf6aurt3bjnfk4) - Low Cost Battery Operated Wireless Arduino Board that can be turned into a IEEE 802.15.4 protocol sniffer.

### SDR Tools

- [RTL-SDR](https://www.rtl-sdr.com/buy-rtl-sdr-dvb-t-dongles/) - Cheapest SDR for beginners. It is a computer based radio scanner for receiving live radio signals frequencies from 500 kHz up to 1.75 GHz.
- [HackRF One](https://greatscottgadgets.com/hackrf/) - Software Defined Radio peripheral capable of transmission or reception of radio signals from 1 MHz to 6 GHz (half-duplex).
- [YardStick One](https://greatscottgadgets.com/yardstickone/) - Half-duplex sub-1 GHz wireless transceiver.
- [LimeSDR](https://www.crowdsupply.com/lime-micro/limesdr) - Software Defined Radio peripheral capable of transmission or reception of radio signals from 100 KHz to 3.8 GHz (full-duplex).
- [BladeRF 2.0](https://www.nuand.com/bladerf-2-0-micro/) - Software Defined Radio peripheral capable of transmission or reception of radio signals from 47 MHz to 6 GHz (full-duplex).
- [USRP B Series](https://www.ettus.com/product-categories/usrp-bus-series/) - Software Defined Radio peripheral capable of transmission or reception of radio signals from 70 MHz to 6 GHz (full-duplex).

### RFID NFC Tools

- [Proxmark 3 RDV4](https://www.proxmark.com/) - Powerful general purpose RFID tool. From Low Frequency (125kHz) to High Frequency (13.56MHz) tags.
- [ChamaleonMini](http://chameleontiny.com/) - Programmable, portable tool for NFC security analysis.
- [HydraNFC](https://hydrabus.com/hydranfc-1-0-specifications/) - Powerful 13.56MHz RFID / NFC platform. Read / write / crack / sniff / emulate.


## Free Training

- [CSAW Embedded Security Challenge 2019](https://github.com/TrustworthyComputing/csaw_esc_2019) - CSAW 2019 Embedded Security Challenge (ESC).
- [Hardware Hacking 101](https://github.com/rdomanski/hardware_hacking/tree/master/my_talks/Hardware_Hacking_101) - Workshop @ BSides Munich 2019.
- [IoTGoat](https://github.com/scriptingxss/IoTGoat) - IoTGoat is a deliberately insecure firmware based on OpenWrt.
- [Rhme-2015](https://github.com/Riscure/RHme-2015) - First riscure Hack me hardware CTF challenge.
- [Rhme-2016](https://github.com/Riscure/Rhme-2016) - Riscure Hack me 2 is a low level hardware CTF challenge.
- [Rhme-2017/2018](https://github.com/Riscure/Rhme-2017) - Riscure Hack Me 3 embedded hardware CTF 2017-2018.

## Websites

- [Hacking Printers Wiki](http://hacking-printers.net/wiki/index.php/Main_Page) - All things printer.
- [OWASP Embedded Application Security Project](https://owasp.org/www-project-embedded-application-security/) - Development best practices and list of hardware and software tools.
- [OWASP Internet of Things Project](https://owasp.org/www-project-internet-of-things/) - IoT common vulnerabilities and attack surfaces.
- [Router Passwords](https://192-168-1-1ip.mobi/default-router-passwords-list/) - Default login credential database sorted by manufacturer.
- [Siliconpr0n](https://siliconpr0n.org/) - A Wiki/Archive of all things IC reversing.

### Blogs

- [RTL-SDR](https://www.rtl-sdr.com/)
- [/dev/ttyS0's Embedded Device Hacking](http://www.devttys0.com/blog/)
- [Exploiteers](https://www.exploitee.rs/)
- [Hackaday](https://hackaday.com)
- [jcjc's Hack The World](https://jcjc-dev.com/)
- [Quarkslab](https://blog.quarkslab.com/)
- [wrong baud](https://wrongbaud.github.io/)
- [Firmware Security](https://firmwaresecurity.com/)
- [PenTestPartners](https://www.pentestpartners.com/internet-of-things/)
- [Attify](https://blog.attify.com/)
- [Patayu](https://payatu.com/blog)
- [GracefulSecurity - Hardware tag](https://gracefulsecurity.com/category/hardware/)
- [Black Hills - Hardware Hacking tag](https://www.blackhillsinfosec.com/tag/hardware-hacking/)

### Tutorials and Technical Background

- [Azeria Lab](https://azeria-labs.com/) - Miscellaneous ARM related Tutorials.
- [JTAG Explained](https://blog.senr.io/blog/jtag-explained#) - A walkthrough covering UART and JTAG bypassing a protected login shell.
- [Reverse Engineering Serial Ports](http://www.devttys0.com/2012/11/reverse-engineering-serial-ports/) - Detailed tutorial about how to spot debug pads on a PCB.
- [UART explained](https://www.mikroe.com/blog/uart-serial-communication) - An in depth explanation of the UART protocol.

## OWASP Resources

- [OWASP Internet of Things Project](https://owasp.org/www-project-internet-of-things/)
- [OWASP Firmware Security Testing Methodology](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

## IoT Hacking Communities

- [IoT Village](https://www.iotvillage.org/)
- [BuildItSecure.ly](http://builditsecure.ly/)
- [Secure Internet of Things Project (Stanford)](http://iot.stanford.edu/people.html)

## Training Available Through ICS-CERT
- https://ics-cert.us-cert.gov/Training-Available-Through-ICS-CERT

## Interesting Blogs

- <http://iotpentest.com/>
- <https://blog.attify.com>
- <https://payatu.com/blog/>
- <http://jcjc-dev.com/>
- <https://w00tsec.blogspot.in/>
- <http://www.devttys0.com/>
- <https://www.rtl-sdr.com/>
- <https://keenlab.tencent.com/en/>
- <https://courk.cc/>
- <https://iotsecuritywiki.com/>
- <https://cybergibbons.com/>
- <http://firmware.re/>

## CTFs Related to IoT's and Embedded Devices

- <https://github.com/hackgnar/ble_ctf>
- <https://www.microcorruption.com/>
- <https://github.com/Riscure/Rhme-2016>
- <https://github.com/Riscure/Rhme-2017>

## YouTube Channels for Embedded hacking

- [Liveoverflow](https://www.youtube.com/channel/UClcE-kVhqyiHCcjYwcpfj9w)
- [Binary Adventure](https://www.youtube.com/channel/UCSLlgiYtOXZnYPba_W4bHqQ)
- [EEVBlog](https://www.youtube.com/user/EEVblog)
- [JackkTutorials](https://www.youtube.com/channel/UC64x_rKHxY113KMWmprLBPA)
- [Craig Smith](https://www.youtube.com/channel/UCxC8G4Oeed4N0-GVeDdFoSA)

## Reverse Enginnering Tools

- [IDA Pro](https://www.youtube.com/watch?v=fgMl0Uqiey8)
- [GDB](https://www.youtube.com/watch?v=fgMl0Uqiey8)
- [Radare2](https://radare.gitbooks.io/radare2book/content/)

## MQTT

- [Introduction](https://www.hivemq.com/blog/mqtt-essentials-part-1-introducing-mqtt)
- [Hacking the IoT with MQTT](https://morphuslabs.com/hacking-the-iot-with-mqtt-8edaf0d07b9b)
- [thoughts about using IoT MQTT for V2V and Connected Car from CES 2014](https://mobilebit.wordpress.com/tag/mqtt/)
- [Nmap](https://nmap.org/nsedoc/lib/mqtt.html)
- [The Seven Best MQTT Client Tools](https://www.hivemq.com/blog/seven-best-mqtt-client-tools)
- [A Guide to MQTT by Hacking a Doorbell to send Push Notifications](https://youtu.be/J_BAXVSVPVI)

## CoAP

- [Introduction](http://coap.technology/)
- [CoAP client Tools](http://coap.technology/tools.html)
- [CoAP Pentest Tools](https://bitbucket.org/aseemjakhar/expliot_framework)
- [Nmap](https://nmap.org/nsedoc/lib/coap.html)

## Automobile

- [Introduction and protocol Overview](https://www.youtube.com/watch?v=FqLDpHsxvf8)
- [PENTESTING VEHICLES WITH CANTOOLZ](https://www.blackhat.com/docs/eu-16/materials/eu-16-Sintsov-Pen-Testing-Vehicles-With-Cantoolz.pdf)
- [Building a Car Hacking Development Workbench: Part1](https://blog.rapid7.com/2017/07/11/building-a-car-hacking-development-workbench-part-1/)
- [CANToolz - Black-box CAN network analysis framework](https://github.com/CANToolz/CANToolz)

## Radio IoT Protocols Overview

- [Understanding Radio](https://www.taitradioacademy.com/lessons/introduction-to-radio-communications-principals/)
- [Signal Processing]()
- [Software Defined Radio](https://www.allaboutcircuits.com/technical-articles/introduction-to-software-defined-radio/)
- [Gnuradio](https://wiki.gnuradio.org/index.php/Guided_Tutorial_GRC#Tutorial:_GNU_Radio_Companion)
- [Creating a flow graph](https://blog.didierstevens.com/2017/09/19/quickpost-creating-a-simple-flow-graph-with-gnu-radio-companion/)
- [Analysing radio signals](https://www.rtl-sdr.com/analyzing-433-mhz-transmitters-rtl-sdr/)
- [Recording specific radio signal](https://www.rtl-sdr.com/freqwatch-rtl-sdr-frequency-scanner-recorder/)
- [Replay Attacks](https://www.rtl-sdr.com/tutorial-replay-attacks-with-an-rtl-sdr-raspberry-pi-and-rpitx/)

## Base transceiver station (BTS)

- [what is base tranceiver station](https://en.wikipedia.org/wiki/Base_transceiver_station)
- [How to Build Your Own Rogue GSM BTS](https://www.evilsocket.net/2016/03/31/how-to-build-your-own-rogue-gsm-bts-for-fun-and-profit/)

## GSM & SS7 Pentesting

- [Introduction to GSM Security](http://www.pentestingexperts.com/introduction-to-gsm-security/)
- [GSM Security 2](https://www.ehacking.net/2011/02/gsm-security-2.html)
- [vulnerabilities in GSM security with USRP B200](https://ieeexplore.ieee.org/document/7581461/)
- [Security Testing 4G (LTE) Networks](https://labs.mwrinfosecurity.com/assets/BlogFiles/mwri-44con-lte-presentation-2012-09-11.pdf)
- [Case Study of SS7/SIGTRAN Assessment](https://nullcon.net/website/archives/pdf/goa-2017/case-study-of-SS7-sigtran.pdf)
- [Telecom Signaling Exploitation Framework - SS7, GTP, Diameter & SIP](https://github.com/SigPloiter/SigPloit)
- [ss7MAPer – A SS7 pen testing toolkit](https://n0where.net/ss7-pentesting-toolkit-ss7maper)
- [Introduction to SIGTRAN and SIGTRAN Licensing](https://www.youtube.com/watch?v=XUY6pyoRKsg)
- [SS7 Network Architecture](https://youtu.be/pg47dDUL1T0)
- [Introduction to SS7 Signaling](https://www.patton.com/whitepapers/Intro_to_SS7_Tutorial.pdf)

## Zigbee & Zwave

- [Introduction and protocol Overview](http://www.informit.com/articles/article.aspx?p=1409785)
- [Hacking Zigbee Devices with Attify Zigbee Framework](https://blog.attify.com/hack-iot-devices-zigbee-sniffing-exploitation/)
- [Hands-on with RZUSBstick](https://uk.rs-online.com/web/p/radio-frequency-development-kits/6962415/)
- [ZigBee & Z-Wave Security Brief](http://www.riverloopsecurity.com/blog/2018/05/zigbee-zwave-part1/)

## BLE

- [Traffic Engineering in a Bluetooth Piconet](http://www.diva-portal.org/smash/get/diva2:833159/FULLTEXT01.pdf)
- [BLE Characteristics](https://devzone.nordicsemi.com/tutorials/b/bluetooth-low-energy/posts/ble-characteristics-a-beginners-tutorial0) Reconnaissance (Active and Passive) with HCI Tools

  - [btproxy](https://github.com/conorpp/btproxy)
  - [hcitool & bluez](https://www.pcsuggest.com/linux-bluetooth-setup-hcitool-bluez)
  - [Testing With GATT Tool](https://www.jaredwolff.com/blog/get-started-with-bluetooth-low-energy/)
  - [Cracking encryption](https://github.com/mikeryan/crackle)

## Mobile security (Android & iOS)

- [Android](https://www.packtpub.com/hardware-and-creative/learning-pentesting-android-devices)
- [Android Pentest Video Course](https://www.youtube.com/watch?v=zHknRia3I6s&list=PLWPirh4EWFpESLreb04c4eZoCvJQJrC6H)
- [IOS Pentesting](https://web.securityinnovation.com/hubfs/iOS%20Hacking%20Guide.pdf?)

## ARM

- [Azeria Labs](https://azeria-labs.com/)
- [ARM EXPLOITATION FOR IoT](https://www.exploit-db.com/docs/english/43906-arm-exploitation-for-iot.pdf)

## Firmware Pentest

- [Firmware analysis and reversing](https://www.youtube.com/watch?v=G0NNBloGIvs)
- [Firmware emulation with QEMU](https://www.youtube.com/watch?v=G0NNBloGIvs)
- [Dumping Firmware using Buspirate](http://iotpentest.com/tag/pulling-firmware/)

## IoT hardware Overview

- [IoT Hardware Guide](https://www.postscapes.com/internet-of-things-hardware/)

## Hardware Tools

- [Bus Pirate](https://www.sparkfun.com/products/12942)
- [EEPROM readers](https://www.ebay.com/bhp/eeprom-reader)
- [Jtagulator / Jtagenum](https://www.adafruit.com/product/1550)
- [Logic Analyzer](https://www.saleae.com/)
- [The Shikra](https://int3.cc/products/the-shikra)
- [FaceDancer21 (USB Emulator/USB Fuzzer)](https://int3.cc/products/facedancer21)
- [RfCat](https://int3.cc/products/rfcat)
- [IoT Exploitation Learning Kit](https://www.attify.com/attify-store/iot-exploitation-learning-kit)
- [Hak5Gear- Hak5FieldKits](https://hakshop.com/)
- [Ultra-Mini Bluetooth CSR 4.0 USB Dongle Adapter](https://www.ebay.in/itm/Ultra-Mini-Bluetooth-CSR-4-0-USB-Dongle-Adapter-Black-Golden-with-2-yr-wrnty-/332302813975)
- [Attify Badge - UART, JTAG, SPI, I2C (w/ headers)](https://www.attify-store.com/products/attify-badge-assess-security-of-iot-devices)

## Hardware Interfaces

- [Serial Terminal Basics](https://learn.sparkfun.com/tutorials/terminal-basics/all)
- [Reverse Engineering Serial Ports](http://www.devttys0.com/2012/11/reverse-engineering-serial-ports/)

### UART

- [Identifying UART interface](https://www.mikroe.com/blog/uart-serial-communication)
- [onewire-over-uart](https://github.com/dword1511/onewire-over-uart)
- [Accessing sensor via UART](http://home.wlu.edu/~levys/courses/csci250s2017/SensorsSignalsSerialSockets.pdf)

### JTAG

- [Identifying JTAG interface](https://blog.senr.io/blog/jtag-explained)
- [NAND Glitching Attack](http://www.brettlischalk.com/posts/nand-glitching-wink-hub-for-root)
