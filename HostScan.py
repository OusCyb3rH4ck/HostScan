#!/usr/bin/env python3

from colorama import Fore, Style
from mac_vendor_lookup import MacLookup
import scapy.all as scapy
import sys, os, signal

def handler(sig, frame):
    print(Fore.RED + Style.DIM + "\n\n[!] Exiting...\n" + Fore.WHITE + Style.NORMAL)
    sys.exit(1)

signal.signal(signal.SIGINT, handler)

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    devices = []
    mac_lookup = MacLookup()
    for element in answered_list:
        mac = element[1].hwsrc
        try:
            vendor = mac_lookup.lookup(mac)
        except Exception:
            vendor = "Unknown Vendor"
        device = {"ip": element[1].psrc, "mac": mac, "vendor": vendor}
        devices.append(device)
    return devices

def show_results(results):
    sorted_results = sorted(results, key=lambda x: int(x['ip'].split('.')[-1]))
    print(f"\n\n{Style.BRIGHT + Fore.CYAN}IP\t\t\tMAC Address\t\t\tVendor")
    print(Style.DIM + "------------------------------------------------------------------------" + Fore.RESET + Style.RESET_ALL)
    for device in sorted_results:
        print(f"{device['ip']}\t\t{device['mac']}\t\t{device['vendor']}")

if __name__ == "__main__":
    os.system("clear && figlet HostScan")
    print(Style.BRIGHT + Fore.GREEN + "Made by OusCyb3rH4ck" + Fore.RESET + Style.RESET_ALL)
    
    if len(sys.argv) != 2:
        print("\n\nUsage: sudo python3 HostScan.py <IP/Range> (ex. 192.168.1.0/24)\n")
        sys.exit(1)

    ip_to_scan = sys.argv[1]
    results = scan(ip_to_scan)
    show_results(results)
    print("\n")
