# Useful `tcpdump` commands

### TCPDUMP Cheat Sheet
* [TCPDUMP Cheat Sheet](http://packetlife.net/media/library/12/tcpdump.pdf) is a good resource (I also have a local copy in this repository)

### TCP traffic on port 80-88
`tcpdump -nvvX -sO -i ethO tcp portrange 80-88`

### Capturing traffic to specific IP address excluding specific subnet
`tcpdump -I ethO -tttt dst ip and not net 10.10.10.0/24`

### Capturing traffic for a specific host
`tcpdump host 10.1.1.1`

### Capturing traffic for a specific subnet
`tcpdump net 10.1.1`

### Capturing traffic for a given duration in seconds
`dumpcap -I ethO -a duration: sec -w file myfile.pcap`

### Replaying a PCAP
`file2cable -i ethO -f file.pcap`

### Replaying packets (to fuzz/DoS)
`tcpreplay--topspeed --loop=O --intf=ethO pcap_file_to_replay mbps=10|100|1000
