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
import uuid
import SecurityContext
from scapy.all import *

ARP_PORT = 7777
DHCP_PORT = 8888
CA_PORT = 9999
ARP_SIZE = 28 + 256# + 294# need to update for nounce

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
            print("[*] Connected to %s Port %s" % (str(ip), str(port)) )
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
            #print("Error [line %d]: %s" % (exc_tb.tb_lineno,str(e)))

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
            # print("Error unpacking data [line %d]: %s" % (exc_tb.tb_lineno,str(e)))

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
        self.sig_size = 256
        self.nonce_size = 36
        self.valid = False

        if raw:
            self.__from_raw(raw)

    def __from_raw(self, raw):
        arp = raw[:self.arp_size]
        sig = raw[self.arp_size:]

        if len(sig) != self.sig_size:
            print("Error in parsing raw Secure Arp Packet: bad sig")
            return

        if len(sig) == 0:
            print("Error: No signature in ARP packet")
            return

        try:
            pkt = ARP(arp)
        except Exception, e:
            print("Error in parsing raw Secure Arp Packet: %s" % str(e))
            return

        self.pkt = pkt
        self.sig = sig

    def create_query(self, src_mac, src_ip, query_ip):
        try:
            self.pkt = ARP(op=ARP.who_has, hwsrc=src_mac, psrc=src_ip, hwdst='ff:ff:ff:ff:ff:ff', pdst=query_ip)
        except Exception, e:
            print("Error in creating raw Secure Arp Packet: %s" % str(e))
            return None

        self.sig = self.create_nonce()
        self.valid = True
        return self.sig

    def get_query_ip(self):
        if self.pkt.op == ARP.is_at: #if its not a query
            return None

        return self.pkt.pdst

    # assuming packet already represents valid (parsed) query
    def create_response(self, src_mac, src_ip, keys):
        self.pkt.op = ARP.is_at
        self.pkt.hwdst = self.pkt.hwsrc # send back to host who sent query
        self.pkt.hwsrc = src_mac
        self.pkt.pdst = self.pkt.psrc
        self.pkt.psrc = src_ip
        # response arp is now ready, set sig
        self.create_sig(keys)

    def create_nonce(self):
        data = str(uuid.uuid4())
        pad_len = self.sig_size - len(data)
        pad = "X" * pad_len
        data += pad
        # debug("Nonce: " + data)
        return data

    def create_sig(self, keys):
        nonce = self.sig # nonce + pad, just sign all
        debug("Signing nonce: " + nonce + " len " + str(len(nonce)))
        c = SecurityContext.AsymmetricCrypto(publicKey=keys.publicKey.exportKey('DER'), privateKey=keys.privateKey.exportKey('DER'))
        self.sig = c.sign(nonce)

    def validate_sig(self, nonce, key):
        valid = SecurityContext.verify(nonce, self.sig, key)
        return valid

    def serialize(self):
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

'''
Simple test for sending and parsing arp packets
'''
def main():
    pass

if __name__ == '__main__':
    main()
