'''
Driver script for running secure ARP protocol
'''

import NetworkManager
import SecurityContext

import socket
import argparse

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
        NetworkManager.dhcp_mode()
    elif args[1]:
        NetworkManager.ca_mode(args[1])
    else:
        NetworkManager.host_mode(args[2])

if __name__ == '__main__':
    main()