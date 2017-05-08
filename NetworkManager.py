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
# Class definitions for Socket and SecureArp

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
        print("Listening on %s" % str(self.sock.getsockname()))
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
        print("Sending to %s" % str(sock.getsockname()))
        length = struct.pack("I", len(msg))

        if self.tcp:
            sock.send(length + msg)
        else:
            sock.sendto(length + msg, dest)


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

    def is_query(self):
        if self.pkt.op == ARP.who_has:
            return True

        return False

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


def _broadcast_packet(data, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    print("Sending broadcast to %s" % str(port))
    sock.sendto(data, ('127.0.0.1', port))
    #sock.sendto(data, ('255.255.255.255', port))

# Modes for nodes to continuously run in


'''
Connect to CA, continuously check file for update and send to CA
@arg port to bind to
'''
def dhcp_mode():
    s = Socket('', DHCP_PORT, server=True, tcp=True)
    s.wait_for_conn()
    # loop and send updates... simple echo for now
    s.send_message("Hello")
    #time.sleep(2)
    data = s.tcp_recv_message(wait=True) # data can be null
    print(data)

'''
Connect to DHCP server and receive updates
Listen on a port for queries
@arg ip of DHCP server
'''
def ca_mode(dhcp_ip):
    # Set up DHCP conn
    dhcp_sock = Socket(dhcp_ip, DHCP_PORT, tcp=True)
    data = dhcp_sock.tcp_recv_message(wait=True)
    print(data)
    dhcp_sock.send_message("Roger")

    # Listen on DHCP port AND CA port for queries
    # TODO use threads
    ca_sock = Socket('', CA_PORT, server=True)
    while True:
        data = dhcp_sock.tcp_recv_message()
        if data:
            print("[*] Received update from DHCP")
            ca_handle_dhcp(data, dhcp_sock)

        if ca_sock.check_for_udp_conn():
            ca_handle_query(ca_sock) # handles query and kills conn


def host_mode(query_ip, port):
    # Assuming host's IP and public key already registered with CA
    # Send query, if any. Otherwise, listen on port to respond
    sock = Socket('127.0.0.1', port, server=True)
    if query_ip:
        arp_query = SecureArp()
        if not arp_query.create_query('6c:40:08:bc:f6:ca', '127.0.0.1', query_ip):
            print("Error: Couldnt create ARP query for ip %s" % str(query_ip))
        else:
            _broadcast_packet(arp_query.serialize(), ARP_PORT)

    print("[*] Listening for ARP messages on port %s" % str(port))
    while True:
        # if query, respond to it. If response, validate and add to table
        data, addr = sock.udp_recv_message(ARP_SIZE, wait=True)
        if data:
            response_arp = SecureArp(raw=data)
            if response_arp.is_query():
                print("[*] Received Query from %s" % str(addr))
                response_arp.pkt.show()
                if response_arp.create_response('d0:e7:82:dc:37:60', '127.0.0.1'):
                    sock.send_message(response_arp.serialize(), dest=addr)
                else:
                    print("Error in creating ARP response!")
            else:
                #if response_arp.validate_sig():
                #    pass
                print("[*] Received response:")
                response_arp.pkt.show()

    pass

def ca_handle_dhcp(data, dhcp_sock):
    pass

def ca_handle_query(ca_sock):
    pass

'''
Simple test for sending and parsing arp packets
'''
def main():
    pass

if __name__ == '__main__':
    main()