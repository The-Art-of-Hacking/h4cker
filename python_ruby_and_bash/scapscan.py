#!/usr/bin/python
"""
Author: Omar Santos @santosomar
version 1.0
This is a quick demonstration on how to use the scapy as a scanner
* Pre-requisite: scapy, prettytable, argparse
"""
from __future__ import print_function

import sys
import prettytable
import argparse
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) #This is supress scapy warnings

from scapy.all import *

#conf.iface='eth0' # network interface to use
conf.verb=0 # enable verbose mode - Is this actually working?
conf.nofilter=1

def tcp_connect_scan(dst_ip,dst_port,dst_timeout):
    src_port = RandShort()
    tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=dst_timeout)
    if(str(type(tcp_connect_scan_resp))=="<type 'NoneType'>"):
        return "Closed"
    elif(tcp_connect_scan_resp.haslayer(TCP)):
        if(tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=dst_timeout)
            return "Open"
        elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):
            return "Closed"
    else:
        return "CHECK"


def stealth_scan(dst_ip,dst_port,dst_timeout):
    src_port = RandShort()
    stealth_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=dst_timeout)
    if(str(type(stealth_scan_resp))=="<type 'NoneType'>"):
        return "Filtered"
    elif(stealth_scan_resp.haslayer(TCP)):
        if(stealth_scan_resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="R"),timeout=dst_timeout)
            return "Open"
        elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
            return "Closed"
    elif(stealth_scan_resp.haslayer(ICMP)):
        if(int(stealth_scan_resp.getlayer(ICMP).type)==3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return "Filtered"
    else:
        return "CHECK"


def xmas_scan(dst_ip,dst_port,dst_timeout):
    xmas_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="FPU"),timeout=dst_timeout)
    if (str(type(xmas_scan_resp))=="<type 'NoneType'>"):
        return "Open|Filtered"
    elif(xmas_scan_resp.haslayer(TCP)):
        if(xmas_scan_resp.getlayer(TCP).flags == 0x14):
            return "Closed"
    elif(xmas_scan_resp.haslayer(ICMP)):
        if(int(xmas_scan_resp.getlayer(ICMP).type)==3 and int(xmas_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return "Filtered"
    else:
        return "CHECK"


def fin_scan(dst_ip,dst_port,dst_timeout):
    fin_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="F"),timeout=dst_timeout)
    if (str(type(fin_scan_resp))=="<type 'NoneType'>"):
        return "Open|Filtered"
    elif(fin_scan_resp.haslayer(TCP)):
        if(fin_scan_resp.getlayer(TCP).flags == 0x14):
            return "Closed"
    elif(fin_scan_resp.haslayer(ICMP)):
        if(int(fin_scan_resp.getlayer(ICMP).type)==3 and int(fin_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return "Filtered"
    else:
        return "CHECK"


def null_scan(dst_ip,dst_port,dst_timeout):
    null_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags=""),timeout=dst_timeout)
    if (str(type(null_scan_resp))=="<type 'NoneType'>"):
        return "Open|Filtered"
    elif(null_scan_resp.haslayer(TCP)):
        if(null_scan_resp.getlayer(TCP).flags == 0x14):
            return "Closed"
    elif(null_scan_resp.haslayer(ICMP)):
        if(int(null_scan_resp.getlayer(ICMP).type)==3 and int(null_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return "Filtered"
    else:
        return "CHECK"


def ack_flag_scan(dst_ip,dst_port,dst_timeout):
    ack_flag_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="A"),timeout=dst_timeout)
    if (str(type(ack_flag_scan_resp))=="<type 'NoneType'>"):
        return "Stateful firewall present\n(Filtered)"
    elif(ack_flag_scan_resp.haslayer(TCP)):
        if(ack_flag_scan_resp.getlayer(TCP).flags == 0x4):
            return "No firewall\n(Unfiltered)"
    elif(ack_flag_scan_resp.haslayer(ICMP)):
        if(int(ack_flag_scan_resp.getlayer(ICMP).type)==3 and int(ack_flag_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return "Stateful firewall present\n(Filtered)"
    else:
        return "CHECK"


def window_scan(dst_ip,dst_port,dst_timeout):
    window_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags="A"),timeout=dst_timeout)
    if (str(type(window_scan_resp))=="<type 'NoneType'>"):
        return "No response"
    elif(window_scan_resp.haslayer(TCP)):
        if(window_scan_resp.getlayer(TCP).window == 0):
            return "Closed"
        elif(window_scan_resp.getlayer(TCP).window > 0):
            return "Open"
    else:
        return "CHECK"


def udp_scan(dst_ip,dst_port,dst_timeout):
    udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout)
    if (str(type(udp_scan_resp))=="<type 'NoneType'>"):
        retrans = []
        for count in range(0,3):
            retrans.append(sr1(IP(dst=dst_ip)/UDP(dport=dst_port),timeout=dst_timeout))
        for item in retrans:
            if (str(type(item))!="<type 'NoneType'>"):
                udp_scan(dst_ip,dst_port,dst_timeout)
        return "Open|Filtered"
    elif (udp_scan_resp.haslayer(UDP)):
        return "Open"
    elif(udp_scan_resp.haslayer(ICMP)):
        if(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code)==3):
            return "Closed"
        elif(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
            return "Filtered"
    else:
        return "CHECK"

def start(your_target,your_ports,your_timeout):
    x = prettytable.PrettyTable(["Port No.","TCP Connect Scan","Stealth Scan","XMAS Scan","FIN Scan","NULL Scan", "ACK Flag Scan", "Window Scan", "UDP Scan"])
    x.align["Port No."] = "l"

    user_dst_ip = your_target
    port_list = your_ports
    user_dst_timeout = your_timeout

    print("[+] Target : %s\n" % user_dst_ip)
    print("[*] Scan started\n")

    for i in port_list:
        tcp_connect_scan_res = tcp_connect_scan(user_dst_ip,int(i),int(user_dst_timeout))
        stealth_scan_res = stealth_scan(user_dst_ip,int(i),int(user_dst_timeout))
        xmas_scan_res = xmas_scan(user_dst_ip,int(i),int(user_dst_timeout))
        fin_scan_res = fin_scan(user_dst_ip,int(i),int(user_dst_timeout))
        null_scan_res = null_scan(user_dst_ip,int(i),int(user_dst_timeout))
        ack_flag_scan_res = ack_flag_scan(user_dst_ip,int(i),int(user_dst_timeout))
        window_scan_res = window_scan(user_dst_ip,int(i),int(user_dst_timeout))
        udp_scan_res = udp_scan(user_dst_ip,int(i),int(user_dst_timeout))
        x.add_row([i,tcp_connect_scan_res,stealth_scan_res,xmas_scan_res,fin_scan_res,null_scan_res,ack_flag_scan_res,window_scan_res,udp_scan_res])
    print(x)

    print("\n[*] Scan completed\n")


def banner():
    bannerTxt = """
************************************************************
  ####   ####    ##   #####   ####   ####    ##   #    #
 #      #    #  #  #  #    # #      #    #  #  #  ##   #
  ####  #      #    # #    #  ####  #      #    # # #  #
      # #      ###### #####       # #      ###### #  # #
 #    # #    # #    # #      #    # #    # #    # #   ##
  ####   ####  #    # #       ####   ####  #    # #    #

A demonstration by Omar Santos on how to use scapy for scanning purposes. Part of the Cybersecurity classes at: https://h4cker.org

This tool supports TCP Connect Scans, Stealth Scans, XMAS Scans, FIN Scans, NULL Scans, ACK Flag Scans, Window Scans, and UDP Scans.

usage: scapy_stealth_scan.py [-h] [-p] [-pl] [-pr] [-t] target

************************************************************
   	"""
    print(bannerTxt)


def main():
    parser = argparse.ArgumentParser(description=banner())
    parser.add_argument("target", help="Target address")
    parser.add_argument("-p", metavar="", help="Single port e.g. 80")
    parser.add_argument("-pl", metavar="", help="Port list e.g. 21,22,80")
    parser.add_argument("-pr", metavar="", help="Port range e.g. 20-30")
    parser.add_argument("-t", metavar="", type=int, default=2, help="Timeout value (default 2)")
    args = parser.parse_args()
    target = args.target

    ports = []
    if args.p:
            p = args.p
            ports.append(p)
    if args.pl:
            pl = (args.pl).split(",")
            ports += pl
    if args.pr:
            pr = (args.pr).split("-")
            pr.sort()
            pr_item1 = int(pr[0])
            pr_item2 = int(pr[1])+1
            new_pr = range(pr_item1,pr_item2,1)
            ports += new_pr

    timeout = int( args.t)

    if(not len(ports)>0):
            print("No ports specified.\nUse -h or --help to see the help menu")
            exit(0)

    ports = list(set(ports))
    new_ports=[]
    for item in ports:
            new_ports.append(int(item))
    ports = new_ports
    ports.sort()

    start(target,ports,timeout)

if __name__ == "__main__":
    main()
