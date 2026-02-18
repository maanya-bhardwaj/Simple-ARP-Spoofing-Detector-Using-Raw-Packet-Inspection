#!/usr/bin/env python3

from scapy.all import ARP, sniff
import time

# Store known IP → MAC mappings
ip_mac_table = {}

def detect_arp_spoof(pkt):
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # is-at (ARP reply)
        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc

        # Check for change in MAC address for known IP
        if src_ip in ip_mac_table:
            if ip_mac_table[src_ip] != src_mac:
                print(f"[ALERT] ARP Spoofing Detected!")
                print(f" - IP: {src_ip}")
                print(f" - MAC changed from {ip_mac_table[src_ip]} to {src_mac}")
        else:
            print(f"[INFO] New ARP entry: {src_ip} → {src_mac}")

        ip_mac_table[src_ip] = src_mac

def main():
    print("🛡️  Starting ARP spoofing detector...")
    print("Press Ctrl+C to stop.\n")
    sniff(filter="arp", store=0, prn=detect_arp_spoof)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n🔚 Detector stopped.")


