from scapy.all import *
import netifaces
import sys

def get_interface():
    for i in netifaces.interfaces():
        if i != "lo":
            return i
    return None

def getMac():
    my_mac = netifaces.ifaddresses(get_interface())[netifaces.AF_LINK][0]['addr']
    return my_mac

p = Ether(dst="ff:ff:ff:ff:ff:ff",src=getMac())/ARP(hwsrc=getMac(),pdst=sys.argv[1])

#p = IP(dst=sys.argv[2])/Ether(dst="ff:ff:ff:ff:ff:ff",src=getMac())/ARP(hwsrc=getMac(),pdst=sys.argv[2])
print p.show()
sendp(p)
#sendp(Ether(dst="00:0c:29:09:ac:56",src="ae:6e:23:98:81:d0")/ARP(hwsrc="ae:6e:23:98:81:d0",pdst="192.168.1.1"))
