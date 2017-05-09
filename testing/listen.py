from scapy.all import *

def handle_packet(pkt):
    print pkt.show()

print sniff(filter="arp", count=0, prn=handle_packet)
