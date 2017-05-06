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

DHCP_PORT = 8888
CA_PORT = 9999

'''
Wrapper over python socket module, for ease of use
'''
class Socket:
    def __init__(self, ip, port, server=False, tcp=False):
        self.server = server
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

    def recv_message(self, wait=False):
        sock = self.sock
        res = None

        if self.server:
            sock = self.conn

        if wait:
            sock.settimeout(None)
        else:
            sock.settimeout(0.0)

        try:
            data = sock.recv(4)
            if len(data) < 4:
                return None #discard
            
            size = struct.unpack("I", data)[0]
            res = sock.recv(int(size))

        except Exception, e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("Error [line %d]: %s" % (exc_tb.tb_lineno,str(e)))

        return res

    def send_message(self, msg):
        sock = self.sock
        if self.server:
            sock = self.conn

        sock.settimeout(None)
        print("Sending to %s" % str(sock.getsockname()))
        length = struct.pack("I", len(msg))
        sock.send(length + msg)

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
    data = s.recv_message(wait=True)
    print(data)

'''
Connect to DHCP server and receive updates
Listen on a port for queries
@arg ip of DHCP server
'''
def ca_mode(dhcp_ip):
    # Set up DHCP conn
    dhcp_sock = Socket(dhcp_ip, DHCP_PORT, tcp=True)
    msg = dhcp_sock.recv_message(wait=True)
    print(msg)
    dhcp_sock.send_message("Roger")

    # Listen on DHCP port AND CA port for queries
    # TODO use threads
    ca_sock = Socket('', CA_PORT, server=True)
    while True:
        data = dhcp_sock.recv_message()
        if data:
            print("[*] Received update from DHCP")
            ca_handle_dhcp(data, dhcp_sock)

        if ca_sock.check_for_udp_conn():
            ca_handle_query(ca_sock) # handles query and kills conn

def host_mode():
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