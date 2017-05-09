#!/usr/bin/python

"""
Example network of Quagga routers
(QuaggaTopo + QuaggaService)
"""

import sys
import atexit

# patch isShellBuiltin
import mininet.util
import mininext.util
mininet.util.isShellBuiltin = mininext.util.isShellBuiltin
sys.modules['mininet.util'] = mininet.util

from mininet.util import dumpNodeConnections
from mininet.node import OVSController
from mininet.log import setLogLevel, info

from mininext.cli import CLI
from mininext.net import MiniNExT

from topo import QuaggaTopo

net = None


def startNetwork():
    "instantiates a topo, then starts the network and prints debug information"

    info('** Creating Quagga network topology\n')
    topo = QuaggaTopo()

    info('** Starting the network\n')
    global net
    net = MiniNExT(topo, controller=OVSController, autoSetMacs = True)
    net.start()

    info('** Dumping host connections\n')
    dumpNodeConnections(net.hosts)

    net['R1'].setIP('192.168.1.65', prefixLen = 24, intf = 'R1-eth1')
    net['R1'].setIP('192.168.1.129', prefixLen = 24, intf = 'R1-eth2')
    net['R1'].setIP('192.168.1.193', prefixLen = 24, intf = 'R1-eth3')

    # H1: Add static routes
    net['H1'].cmd('ip route add default via 192.168.1.2 dev H1-eth0')

    # H2: Add static routes
    net['H2'].cmd('ip route add default via 192.168.1.65 dev H2-eth0')

    # H3: Add static routes
    net['H3'].cmd('ip route add default via 192.168.1.129 dev H3-eth0')

    # H4: Add static routes
    net['H4'].cmd('ip route add default via 192.168.1.193 dev H4-eth0')

    # R1: Add static routes
    net['R1'].cmd('ip route add 192.168.1.1/26 via 192.168.1.2 dev R1-eth0')
    net['R1'].cmd('ip route add 192.168.1.64/26 via 192.168.1.65 dev R1-eth1')
    net['R1'].cmd('ip route add 192.168.1.128/26 via 192.168.1.129 dev R1-eth2')
    net['R1'].cmd('ip route add 192.168.1.192/26 via 192.168.1.193 dev R1-eth3')

    # R1: Configure IP forwarding 
    net['R1'].cmd('sysctl -w net.ipv4.ip_forward=1')

    info('** Testing network connectivity\n')
    net.ping(net.hosts)

    info('** Dumping host processes\n')
    for host in net.hosts:
        host.cmdPrint("ps aux")

    # net['H2'].cmdPrint('ping 192.168.1.2')
    info('** Running CLI\n')
    CLI(net)


def stopNetwork():
    "stops a network (only called on a forced cleanup)"

    if net is not None:
        info('** Tearing down Quagga network\n')
        net.stop()

if __name__ == '__main__':
    # Force cleanup on exit by registering a cleanup function
    atexit.register(stopNetwork)

    # Tell mininet to print useful information
    setLogLevel('info')
    startNetwork()
