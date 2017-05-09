'''
Driver script for running secure ARP protocol
'''

import NetworkManager
import SecurityContext
import os
import ast
import time
import socket
import threading
import argparse
import netifaces
import KeyManager
import struct
import uuid
import ARPTable
from scapy.all import *

from threading import Lock

DEBUG = True

INT_SIZE = 4
QUERY_TYPE = 'QueryType'
GET_QUERY_TYPE = 'GET'
IP_QUERY = 'IP'
NONCE = "NONCE"
CA_IP = "192.168.1.1"
SIG_SIZE = 256

MY_MAC = netifaces.ifaddresses(get_interface())[netifaces.AF_LINK][0]['addr']
MY_IP = netifaces.ifaddresses(get_interface())[netifaces.AF_INET][0]['addr']
arp_table = ARPTable.ARPTable()

def debug(s):
    if DEBUG:
        print("[DEBUG] " + str(s))

def get_interface():
    for i in netifaces.interfaces():
        if i != "lo":
            return i
    return None

class FileMonitor():
    def __init__(self, time, filepath, manager):
        self.lastModificationTime = 0
        self.filepath = filepath
        self.manager = manager
        self.mutex = Lock()

    def monitor(self):
        while True:
            if os.stat(self.filepath).st_mtime != self.lastModificationTime:
                self.lastModificationTime = os.path.getmtime(self.filepath)
                self.mutex.acquire()
                self.manager = create_key_manager()
                self.mutex.release()

def initialize_keys():
    network_ips = ["192.168.1.1", "192.168.1.64", "192.168.1.128", "192.168.1.192",\
             "192.168.1.2", "192.168.1.65", "192.168.1.129", "182.168.1.193"]

    debug("GENERATING KEYS")

    with open("DHCP/state.txt", "w") as stateFile:
        map = {}
        for ip in network_ips:
            debug(ip)
            security = SecurityContext.AsymmetricCrypto()
            map[ip] = {"public":security.publicKey.exportKey('DER'),\
                    "private":security.privateKey.exportKey('DER')}

        state = {}
        for ip in map:
            state[ip] = map[ip]['public']

        stateFile.write(str(state))

    for ip in map:
        with open("KEYS/"+ip,"w") as keyFile:
            keyFile.write(str(map[ip]))
    debug("Done")

def create_key_manager():
    with open("DHCP/state.txt","r") as stateFile:
        state = ast.literal_eval(stateFile.read())
        key_manager = KeyManager.KeyManager(state)
        return key_manager

'''
Connect to DHCP server and receive updates
Listen on a port for queries
@arg ip of DHCP server
'''
def ca_mode():

    FILEPATH = "DHCP/state.txt"

    if not os.path.isfile(FILEPATH):
        initialize_keys()
    else:
        print "File exists"

    # Key manager
    key_manager = create_key_manager()

    monitor = FileMonitor(time.time(), FILEPATH, key_manager)

    server_thread = threading.Thread(target=monitor.monitor)
    # Dont exit the server thread when the main thread terminates
    server_thread.daemon = True
    server_thread.start()
    ca_sock = NetworkManager.Socket(CA_IP, NetworkManager.CA_PORT, server=True)

    my_ip = netifaces.ifaddresses(get_interface())[netifaces.AF_INET][0]['addr']
    # Read keys from file and initialize keys object - (pub,priv)
    keys = read_keys(my_ip)

    while True:
        query_size, addr = ca_sock.udp_recv_message(INT_SIZE, wait=True)
        if query_size:
            print("[*] Received update from host", str(addr[0]))
            monitor.mutex.acquire()
            ca_handle_query(monitor.manager, query_size, ca_sock, keys) # handles query and kills conn
            monitor.mutex.release()

def read_keys(ip_addr):
    keys_str = ""
    with open("KEYS/"+ip_addr, "r") as keysFile:
        for line in keysFile:
            keys_str+=line
    keys_map = ast.literal_eval(keys_str)
    keys = SecurityContext.AsymmetricCrypto(publicKey=keys_map["public"], 
        privateKey=keys_map["private"])
    return keys

def handle_arp_request(pkt):
    if pkt[ARP].hwdst == MY_MAC and 
        pkt[ARP].pdst == MY_IP:
        desired_ip = arp_table.psrc
        desired_mac = arp_table.hwsrc
        if arp_table.has(desired_ip):
            arp_table.update(desired_ip, desired_mac)
        else:
            arp_table.add(desired_ip, desired_mac)

def listen_arp_requests():
    print("[*] Listening for ARP messages")
    sniff(filter="arp", prn=handle_arp_request, store=0)

'''
First sends a query, if any. Then listens on port for ARP queries and responds to them
@arg query_ip the ip to send an ARP query for
'''
def host_mode(query_ip):
    # Assuming host's IP and public key already registered with CA
    # Send query, if any. Otherwise, listen on port to respond

    # Read keys from file and initialize keys object - (pub,priv)
    keys = read_keys(MY_IP)

    nonce = None

    sock = NetworkManager.Socket(MY_IP, NetworkManager.ARP_PORT, server=True)
    if query_ip:
        arp_query = NetworkManager.SecureArp()
        nonce = arp_query.create_query(MY_MAC, MY_IP, query_ip)
        if not nonce:
            print("Error: Couldnt create ARP query for ip %s" % str(query_ip))
        else:
            debug("Broadcasting ARP query")
            NetworkManager.broadcast_packet(arp_query.serialize(), NetworkManager.ARP_PORT)
    key_manager = KeyManager.KeyManager()

    arp_thread = threading.Thread(target=listen_arp_requests)
    arp_thread.daemon = True
    arp_thread.start()

    while True:
        # if query, respond to it. If response, validate and add to table
        data, addr = sock.udp_recv_message(NetworkManager.ARP_SIZE, wait=True)
        debug("Received " + str(len(data)) + " bytes")
        if data and addr[0] != MY_IP:
            response_arp = NetworkManager.SecureArp(raw=data)
            query_ip = response_arp.get_query_ip()

            if query_ip:
                print("[*] Received Query from %s" % str(addr))
                response_arp.pkt.show()

                if query_ip == MY_IP:
                    response_arp.create_response(MY_MAC, MY_IP, keys)
                    print("Sending Response:")
                    response_arp.pkt.show()
                    d = (addr[0],NetworkManager.ARP_PORT)
                    sock.send_message(response_arp.serialize(), dest=d)
            else:
                # check cache for key, or send query if not there
                debug(addr)
                sender_ip = addr[0]
                key = None
                if key_manager.has(sender_ip):
                    key = key_manager.get(sender_ip)
                else:
                    key = get_public_key(sock, sender_ip)
                    if not key:
                        print("Detected Invalid Response from CA: bad sig!")
                        continue

                if nonce:
                    # check cache for key or query CA
                    if response_arp.validate_sig(nonce, key):
                        print("[*] Received Valid Response:")
                        response_arp.pkt.show()
                    else:
                        print("[*] Received Invalid Response from %s" % str(addr))
                # Update ARP table

def get_public_key(sock, ip):
    ca_sock = NetworkManager.Socket(CA_IP, NetworkManager.CA_PORT)
    nonce = str(uuid.uuid4())
    debug("Generated nonce for CA: " + nonce)
    query = {QUERY_TYPE: GET_QUERY_TYPE, IP_QUERY: ip, NONCE: nonce}

    ca_sock.send_message(struct.pack("!I", len(query)), (CA_IP, NetworkManager.CA_PORT))
    ca_sock.send_message(str(query), (CA_IP, NetworkManager.CA_PORT))
    data, addr = ca_sock.udp_recv_message(INT_SIZE, wait=True)
    query_size = int(struct.unpack("!I", data)[0])

    data, addr = ca_sock.udp_recv_message(query_size, wait=True)
    debug("Received " + str(len(data)) + " bytes")
    ca_keys = read_keys(CA_IP)

    sig = data[:SIG_SIZE]
    public_key = data[SIG_SIZE:]
    if not validate_sig(nonce, sig, ca_keys.publicKey.exportKey('DER')):
        return None
    debug("Validated Sig from CA")
    return public_key

'''
Handle a public key query from a node
@arg socket to node - UDP
'''
def ca_handle_query(key_manager, query_size, ca_sock, keys):
    query_size = int(struct.unpack("I", query_size)[0])
    data, addr = ca_sock.udp_recv_message(query_size, True)
    query = eval(data)
    query_type = query[QUERY_TYPE]
    if query_type == GET_QUERY_TYPE:
        ip = query[IP_QUERY]
    nonce = query[NONCE]
    public_key = key_manager.get(ip)

    sig = create_sig(nonce, keys)
    payload = sig + public_key
    dest = (addr[0], NetworkManager.ARP_PORT)
    # Send public key size first and then public key
    debug("Sending payload len " + str(len(payload)))
    ca_sock.send_message(struct.pack("!I", len(payload)), dest=addr)
    ca_sock.send_message(payload, dest=addr)

'''
Add ip-public key mapping to table
@arg ip-public key mapping
@arg socket to dhcp server (to send data)
'''
def ca_handle_dhcp(key_manager, data, dhcp_sock):
    key_map = eval(data)
    key_manager.update(key_map)

def create_sig(nonce, keys):
    debug("Signing nonce " + nonce)
    sig = keys.sign(nonce)
    debug("Signed nonce, len=" + str(len(sig)))
    return sig

def validate_sig(nonce, sig, public_key):
    return SecurityContext.verify(nonce, sig, public_key)

# secure_arp.py [-d] [-c ip] [-q ip]
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', action="store_true", help='DHCP server mode')
    parser.add_argument('-q', metavar='IP addr', help='Send secure ARP query for an ip')
    res = parser.parse_args()


    if res.q:
        if res.c:
            print("Error: cannot be send query as DHCP server or Certificate Authority!")
            parser.print_help()
            sys.exit(1)

        try:
            socket.inet_aton(res.q[0])
        except socket.error:
            print("Error: Invalid IP supplied: %s\n" % res.q[0])
            sys.exit(1)

    return (res.c,res.q)


def main():
    args = parse_args()
    if args[0]:
        ca_mode()
    else:
        host_mode(args[1])
if __name__ == '__main__':
    main()
