#!/usr/bin/env python

import scapy.all as scapy
import optparse

def get_command():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Give target ip / ip range")
    (command, argument) = parser.parse_args()
    return command


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]


    clients_list = []
    for value in answered_list:
        clients_dict = {"ip":value[1].psrc, "mac": value[1].hwsrc}
        clients_list.append(clients_dict)

    return clients_list

def print_result(results_list):
    print("IP\t\t\tMAC Address\n-------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

command = get_command()
scan_result = scan(command.target)
print_result(scan_result)


