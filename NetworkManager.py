'''
Class for handling all network connections for Secure ARP

Supports creating, sending, and parsing secure ARP packets
'''

import argparse
import os
import socket
import sys
import time
import struct
from scapy.all import *

ARP_PORT = 7777
DHCP_PORT = 8888
CA_PORT = 9999
ARP_SIZE = 36 # need to update for nounce

DEBUG = True

def debug(s):
    if DEBUG:
        print("[DEBUG] " + str(s))

'''
Wrapper over python socket module, for ease of use
'''
class Socket:
    def __init__(self, ip, port, server=False, tcp=False):
        self.server = server
        self.tcp = tcp
        if tcp:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        if server:
            s.bind((ip, port))
            if tcp:
                s.listen(5)
            self.sock = s

        else:
            s.connect((ip, port))
            print("[*] Connected to %s" % str(ip))
            self.sock = s

    def kill_conn(self):
        if self.server:
            self.conn.close()
            self.conn = None

    def wait_for_conn(self):
        if self.server:
            conn, addr = self.sock.accept()
            print("[*] Accepted connection from %s" % str(addr))
            self.conn = conn

    # TODO implement
    def check_for_udp_conn(self):
        pass

    def __recv(self, size, blocking):
        data = None
        sock = self.sock

        if self.server:
            sock = self.conn

        if blocking:
            sock.settimeout(None)
        else:
            sock.settimeout(0.0)

        try:
            if self.tcp:
                data = sock.recv(size)
        except Exception, e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("Error [line %d]: %s" % (exc_tb.tb_lineno,str(e)))

        return data

    def tcp_recv_message(self, wait=False):
        data = self.__recv(4, wait)
        if not data:
            return None

        try:            
            size = int(struct.unpack("I", data)[0])
        except Exception, e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("Error unpacking data [line %d]: %s" % (exc_tb.tb_lineno,str(e)))

        data = self.__recv(size, wait)

        return data

    def udp_recv_message(self, size, wait=False):
        debug("Listening on UDP %s" % str(self.sock.getsockname()))
        data = None
        addr = None
        if wait:
            self.sock.settimeout(None)
        else:
            self.sock.settimeout(0.0)

        try:
            data, addr = self.sock.recvfrom(size)
        except Exception, e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("Error unpacking data [line %d]: %s" % (exc_tb.tb_lineno,str(e)))

        return data, addr

    def send_message(self, msg, dest=None):
        sock = self.sock
        if self.tcp and self.server:
            sock = self.conn

        sock.settimeout(None)
        length = struct.pack("I", len(msg))

        if self.tcp:
            debug("Sending to %s" % str(sock.getsockname()))
            sock.send(length + msg)
        else:
            debug("Sending %d bytes to %s" % (len(msg),str(dest)))
            sock.sendto(msg, dest)

'''
Class to handle parsing and creating SecureArp packets
'''
class SecureArp:
    def __init__(self, raw=None):
        # args = src_mac, src_ip, query_ip
        self.arp_size = 28 # bytes
        self.sig_size = 512
        self.valid = False

        if raw:
            self.valid = self.__from_raw(raw)

    def __from_raw(self, raw):
        arp = raw[:self.arp_size]
        sig = raw[self.arp_size:]
        
        if len(sig) > self.sig_size:
            print("Error in parsing raw Secure Arp Packet")
            return False
        
        if len(sig) == 0:
            print("Error: No signature in ARP packet")
            return False # No sig, discard

        try:
            pkt = ARP(arp)
        except Exception, e:
            print("Error in parsing raw Secure Arp Packet: %s" % str(e))
            return False

        self.pkt = pkt
        if not self.validate_sig(sig):
            print("Error: Bad signature in ARP Packet")
            return False # Bad sig, discard
        
        self.sig = sig

        return True

    def create_query(self, src_mac, src_ip, query_ip):
        try:
            self.pkt = ARP(op=ARP.who_has, hwsrc=src_mac, psrc=src_ip, hwdst='ff:ff:ff:ff:ff:ff', pdst=query_ip)
        except Exception, e:
            print("Error in creating raw Secure Arp Packet: %s" % str(e))
            return False

        self.sig = 'fake_sig' # should be nounce
        self.valid = True
        return True

    def get_query_ip(self):
        if self.pkt.op == ARP.is_at: #if its not a query
            return None

        return self.pkt.pdst

    # assuming packet already represents valid (parsed) query
    def create_response(self, src_mac, src_ip):
        if not self.valid:
            return False

        if self.pkt.op == ARP.who_has: #and self.pkt.pdst == src_ip: # if query is for me TODO fix
            self.pkt.op = ARP.is_at
            self.pkt.hwdst = self.pkt.hwsrc # send back to host who sent query
            self.pkt.hwsrc = src_mac
            self.pkt.pdst = self.pkt.psrc
            self.pkt.psrc = src_ip
            # response arp is now ready, set sig
            if self.create_sig():
                return True

        return False

    def create_sig(self):
        return "fake_sig"

    def validate_sig(self, sig):
        return True

    def serialize(self):
        if not self.valid:
            return None

        data = str(self.pkt) # should be hex string
        data += str(self.sig) # needs to be able to send over network
        return data

def __jank_broadcast(s,data,port):
    subnet = '192.168.1.'
    for x in range(1,255):
        ip = subnet + str(x)
        s.sendto(data, (ip, port))

def broadcast_packet(data, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    debug("Sending broadcast to %s" % str(port))
    __jank_broadcast(sock,data,port)
    #sock.sendto(data, ('127.0.0.1', port))
    #sock.sendto(data, ('192.168.1.255', port))


'''
Simple test for sending and parsing arp packets
'''
def main():
    pass

if __name__ == '__main__':
    main()
