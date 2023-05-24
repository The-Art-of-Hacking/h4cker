# Internet of Things (IoT) Hacking Resources
The Internet of Things (IoT) Hacking Resources refer to an array of tools and frameworks used to ensure the security of IoT devices and networks.

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
- [Embedded Security CTF](https://microcorruption.com) - Microcorruption: Embedded Security CTF.
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
