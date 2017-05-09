from scapy.all import *

def handle_packet(pkt):
    #if Raw in pkt:
    #    print pkt[Raw].show()
    if Padding in pkt:
        print pkt.show()

print sniff(count=0, prn=handle_packet)
