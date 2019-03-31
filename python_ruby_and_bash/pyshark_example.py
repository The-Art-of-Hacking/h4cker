#!/usr/bin/python
# Author: Omar Santos @santosomar
# version 1.0
# This is a quick demonstration on how to use the python pyshark library
#   * Pre-requisite: pyshark python library.
#   * Install it with pip install pyshark
# PyShark is a Python wrapper for tshark,
# allowing python packet parsing using wireshark dissectors.
#####################################################################

import pyshark

# Sniff from interface
capture = pyshark.LiveCapture(interface='eth0')
capture.sniff(timeout=10)
