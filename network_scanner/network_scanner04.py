#!/usr/bin/env python
# compatible with python 2.7

import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target",
                      help="target address to scan (e.g. 1.2.3.4, 1.2.3.1/24)")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error(
            "[-] Please specify an target address, use --help for more info.")
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    result_list = [];
    for element in answered_list:
        item = { "ip": element[1].psrc, "mac": element[1].hwsrc }
        result_list.append(item)

    return result_list

def print_result(result_list):
    print("IP\t\t\tMAC Address\n--------------------------------------------")
    for element in result_list:
        print(element["ip"] + "\t\t" + element["mac"])


options = get_arguments()
scan_result = scan(options.target)
if len(scan_result) > 0:
    print_result(scan_result)
