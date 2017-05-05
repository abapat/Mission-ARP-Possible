'''
Class for handling all network connections for Secure ARP

Supports creating, sending, and parsing secure ARP packets
'''

import socket
import sys
import time
import struct

def recv_msg(socket):
    buf_length_str = recv_length(socket, 4)
    buf_length = struct.unpack('!I', buf_length_str)[0]
    buf_received = recv_length(socket, buf_length)
    return buf_received

def send_msg(socket, msg):
    socket.sendall(struct.pack('!I', len(msg))
    socket.sendall(msg)

def recv_length(socket, length):
    data_received = ''
    while length > 0:
        data_buf = socket.recv(length)
        if not data_buf:
            return None
        else:
            data_received += data_buf
            length -= len(data_buf)
    return data_received

DHCP_IP = '1.1.1.1'
DHCP_PORT = '8888'
MANAGER_PORT = '9999'

class NetworkManager:
    def __init__(self):
        setup_server()
        connect_to_dhcp()

    def setup_server():
        # Create an INET, STREAMing socket
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind the socket to an addr and a well-known port
        self.server.bind(('', MANAGER_PORT))
        # Become a server socket
        self.server.listen(10)

    def send_to_dhcp(msg):
        send_msg(self.dhcp_socket, msg)

    def connect_to_dhcp():
        connected = False
        # Create an INET, STREAMing socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while not connected:
            # Server may not setup yet, so we will try again server is up
            try:
                s.connect((DHCP_IP, DHCP_PORT))
                connected = True
            except socket.error as s_err:
                time.sleep(5)
                connected = False
                continue
        self.dhcp_socket = s

'''
Simple test for sending and parsing arp packets
'''
def main():
    pass


if __name__ == '__main__':
    main()