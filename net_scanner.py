#!/usr/bin/env python

import scapy.all as scapy
import optparse
# def scan(ip):
#     scapy.arping(ip)

# scan("10.0.2.1/24")
def get_arguments():

    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP / IP range")
    (options, arguments) = parser.parse_args()
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #scapy.ls(scapy.Ether()) to know how to set destination , same with arp
    arp_request_broadcast = broadcast/arp_request
    #arp_request_broadcast.show() to show them combined
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose= False)[0]

    client_list = []
    for element in answered_list:
        client_dict ={"ip": element[1].psrc, "mac" : element[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def print_res(result_list):
    print(" IP\t\t\t MAC Address\n--------------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_arguments()
scan_res = scan("10.0.2.1/24")
print_res(scan_res)
