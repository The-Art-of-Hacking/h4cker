# Tshark Cheat Sheet

## List interfaces on which Tshark can capture
```
tshark -D
```

## Capture Packets with Tshark
```
tshark -i eth0 -w capture-file.pcap
```

## Read a Pcap with Tshark
```
tshark -r capture-file.pcap
```

## Filtering Packets from One Host
```
tshark -i eth0 -p -w capture-file.cap host 10.1.2.3
```

## HTTP Analysis with Tshark
The `-T` option specifies that we want to extract fields and with the `-e` options we identify which fields we want to extract.

```
tshark -i eth0 -Y http.request -T fields -e http.host -e http.user_agent
```
## Manipulating other Fields

This command will extract files from an SMB stream and extract them to the location tmpfolder.
```
tshark -nr test.pcap --export-objects smb,tmpfolder
```

This command will do the same except from HTTP, extracting all the files seen in the pcap.
```
tshark -nr test.pcap --export-objects http,tmpfolder
```
