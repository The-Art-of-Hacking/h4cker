# Snort Resources

- [Snort Documents](https://snort.org/documents)
- [Snort Manual](https://github.com/snort3/snort3/releases/download/3.1.6.0/snort_user.pdf)
- [Snort Rules Writing Guide](https://snort-org-site.s3.amazonaws.com/production/document_files/files/000/000/596/original/Rules_Writers_Guide_to_Snort_3_Rules.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIXACIED2SPMSC7GA%2F20211011%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20211011T165700Z&X-Amz-Expires=172800&X-Amz-SignedHeaders=host&X-Amz-Signature=1d5134d3a84db0f7b1ece95fcf98387a0cc32ff131b6c95e6a80d3cd4b616a5c)

## Snort Docker Container

1. Start the Container in your Linux system running Docker (you can use the Ubuntu VM to test).
```
$ docker run --name snort3 -h snort3 -u snorty -w /home/snorty -d -it ciscotalos/snort3 bash
```

2. Enter the Snort Container
```
$ docker exec -it snort3 bash
snorty@snort3:~$ snort
--------------------------------------------------
o")~   Snort++ 3.0.0-267
--------------------------------------------------
Loading /home/snorty/snort3/etc/snort/snort.lua:
Loading snort_defaults.lua:
Finished snort_defaults.lua:
Loading file_magic.lua:
Finished file_magic.lua:
        ssh
        host_cache
        pop
        binder
        stream_tcp
        network
        gtp_inspect
        packets
        dce_http_proxy
        stream_icmp
        normalizer
        ftp_server
        stream_udp
        search_engine
        ips
        dce_smb
        wizard
        appid
        file_id
        ftp_data
        hosts
        smtp
        port_scan
        dce_http_server
        modbus
        dce_tcp
        telnet
        host_tracker
        ssl
        sip
        rpc_decode
        http2_inspect
        http_inspect
        back_orifice
        stream_user
        stream_ip
        classifications
        dnp3
        active
        ftp_client
        daq
        decode
        alerts
        stream
        references
        arp_spoof
        output
        dns
        dce_udp
        imap
        process
        stream_file
Finished /home/snorty/snort3/etc/snort/snort.lua:
--------------------------------------------------
pcap DAQ configured to passive.

Snort successfully validated the configuration (with 0 warnings).
o")~   Snort exiting
snorty@snort3:~$ 
```
