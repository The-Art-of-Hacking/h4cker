#!/usr/bin/env python3
"""Simple TCP probe script to check a host:port and log state."""
import socket
import time
import os

IP = os.environ.get("IP", "192.168.18.1")
PORT = int(os.environ.get("PORT", "22"))
INTERVAL = int(os.environ.get("INTERVAL", "60"))
LOG = os.environ.get("LOG", f"/var/log/tcp_probe_{IP}_{PORT}.log")
TIMEOUT = float(os.environ.get("TIMEOUT", "3"))

while True:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    s = socket.socket()
    s.settimeout(TIMEOUT)
    try:
        s.connect((IP, PORT))
        s.close()
        print(f"{ts} {IP}:{PORT} OPEN")
        with open(LOG, 'a') as f:
            f.write(f"{ts} OPEN\n")
    except Exception:
        print(f"{ts} {IP}:{PORT} CLOSED")
        with open(LOG, 'a') as f:
            f.write(f"{ts} CLOSED\n")
    time.sleep(INTERVAL)
