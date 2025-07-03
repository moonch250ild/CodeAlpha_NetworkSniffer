from scapy.all import *

# Add this line BEFORE sniffing
conf.L3socket = conf.L3socket

def packet_callback(packet):
    if packet.haslayer(IP):
        print(f"Packet: {packet[IP].src} → {packet[IP].dst}")

print("[*] Starting L3 sniffer...")
sniff(prn=packet_callback, store=0, count=10)