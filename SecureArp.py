'''
Driver script for running secure ARP protocol
'''
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import NetworkManager
import SecurityContext

import os
import time
import socket
import threading
import argparse
import netifaces
import KeyManager

DEBUG = True

def debug(s):
    if DEBUG:
        print("[DEBUG] " + str(s))

def get_interface():
    for i in netifaces.interfaces():
        if i != "lo":
            return i
    return None

class FileMonitor(FileSystemEventHandler):
    def __init__(self, time, filepath, socket):
        self.lastModificationTime = 0
        self.filepath = filepath
        self.socket = socket

    def monitor(self):
        while True:
            if os.stat(self.filepath).st_mtime != self.lastModificationTime:
                self.lastModificationTime = os.path.getmtime(self.filepath)
                s.sendMessage("File was updated")

'''
Connect to CA, continuously check file for update and send to CA
@arg port to bind to
'''
def dhcp_mode():
    debug("DHCP mode")

    # Init a socket to connect to the CA when it connects
    s = NetworkManager.Socket('', NetworkManager.DHCP_PORT, server=True, tcp=True)
    s.wait_for_conn()

    monitor = FileMonitor(time.time(), "DHCP/state.txt", s)
    thread = threading.Thread(target=monitor.monitor)
    thread.daemon = True
    thread.start()

    data = s.tcp_recv_message(wait=True) # data can be null
    print(data)

'''
Connect to DHCP server and receive updates
Listen on a port for queries
@arg ip of DHCP server
'''
def ca_mode(dhcp_ip):
    # Set up DHCP conn
    dhcp_sock = NetworkManager.Socket(dhcp_ip, NetworkManager.DHCP_PORT, tcp=True)
    data = dhcp_sock.tcp_recv_message(wait=True)
    print(data)
    dhcp_sock.send_message("Roger")

    # Listen on DHCP port AND CA port for queries
    ca_sock = NetworkManager.Socket('', NetworkManager.CA_PORT, server=True)
    key_manager = KeyManager()
    while True:
        data = dhcp_sock.tcp_recv_message()
        if data:
            print("[*] Received update from DHCP")
            ca_handle_dhcp(data, dhcp_sock)

        if ca_sock.check_for_udp_conn():
            ca_handle_query(key_manager, ca_sock) # handles query and kills conn

'''
First sends a query, if any. Then listens on port for ARP queries and responds to them
@arg query_ip the ip to send an ARP query for
'''
def host_mode(query_ip):
    # Assuming host's IP and public key already registered with CA
    # Send query, if any. Otherwise, listen on port to respond

    my_ip = netifaces.ifaddresses(get_interface())[netifaces.AF_INET][0]['addr']
    my_mac = netifaces.ifaddresses(get_interface())[netifaces.AF_LINK][0]['addr']

    sock = NetworkManager.Socket(my_ip, NetworkManager.ARP_PORT, server=True)
    if query_ip:
        arp_query = NetworkManager.SecureArp()
        if not arp_query.create_query(my_mac, my_ip, query_ip):
            print("Error: Couldnt create ARP query for ip %s" % str(query_ip))
        else:
            debug("Broadcasting ARP query")
            NetworkManager.broadcast_packet(arp_query.serialize(), NetworkManager.ARP_PORT)

    print("[*] Listening for ARP messages")
    while True:
        # if query, respond to it. If response, validate and add to table
        data, addr = sock.udp_recv_message(NetworkManager.ARP_SIZE, wait=True)
        if data and addr[0] != my_ip:
            response_arp = NetworkManager.SecureArp(raw=data)
            query_ip = response_arp.get_query_ip()
            if query_ip:
                print("[*] Received Query from %s" % str(addr))
                response_arp.pkt.show()

                if query_ip == my_ip:
                    if response_arp.create_response(my_mac, my_ip):
                        print("Sending Response:")
                        response_arp.pkt.show()
                        d = (addr[0],NetworkManager.ARP_PORT)
                        sock.send_message(response_arp.serialize(), dest=d)
                    else:
                        print("Error in creating ARP response!")
        else:
            #if response_arp.validate_sig():
            #    pass
            print("[*] Received response:")
            response_arp.pkt.show()
            # Update ARP table

'''
Add ip-public key mapping to table
@arg ip-public key mapping
@arg socket to dhcp server (to send data)
'''
def ca_handle_dhcp(data, dhcp_sock):
    pass

'''
Handle a public key query from a node
** Kills connection (socket.close) at the end **
@arg socket to node - UDP
'''
def ca_handle_query(key_manager, ca_sock):
    data, addr = ca_sock.udp_recv_message("FIX ME", True)
    query = eval(data)
    query_type = query["QueryType"]
    if query_type == 'Get':
        ip = query["QueryIP"]
    public_key = key_manager.get(ip)
    ca_sock.send(public_key)
    ca_sock.close()

# secure_arp.py [-d] [-c ip] [-q ip]
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', action="store_true", help='DHCP server mode')
    parser.add_argument('-c', metavar='IP addr', help='Certificate Authority Mode')
    parser.add_argument('-q', metavar='IP addr', help='Send secure ARP query for an ip')
    res = parser.parse_args()

    if res.c and res.d:
        print("Error: cannot be in CA mode and DHCP mode!")
        parser.print_help()
        sys.exit(1)

    if res.q:
        if res.c or res.d:
            print("Error: cannot be send query as DHCP server or Certificate Authority!")
            parser.print_help()
            sys.exit(1)

        try:
            socket.inet_aton(res.q[0])
        except socket.error:
            print("Error: Invalid IP supplied: %s\n" % res.q[0])
            sys.exit(1)

    if res.c:
        try:
            socket.inet_aton(res.c)
        except socket.error:
            print("Error: Invalid IP supplied: %s\n" % res.c)
            sys.exit(1)

    return (res.d,res.c,res.q)


def main():
    args = parse_args()
    if args[0]:
        dhcp_mode()
    elif args[1]:
        ca_mode(args[1])
    else:
        host_mode(args[2])

if __name__ == '__main__':
    main()
