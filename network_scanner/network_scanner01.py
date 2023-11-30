#!/usr/bin/env python
# compatible with python 2.7

import scapy.all as scapy


def scan(ip):
    scapy.arping(ip)


#scan("172.16.172.1")
scan("172.16.172.1/24")
