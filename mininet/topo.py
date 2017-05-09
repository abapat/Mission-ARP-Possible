"""
Example topology of Quagga routers
"""

import inspect
import os
from mininext.topo import Topo
from mininext.services.quagga import QuaggaService

from collections import namedtuple

QuaggaHost = namedtuple("QuaggaHost", "name ip loIP mac")
net = None


class QuaggaTopo(Topo):

    "Creates a topology of Quagga routers"

    def __init__(self):
        """Initialize a Quagga topology with 4 routers and 2 hosts, configure their IP
           addresses, loop back interfaces, and paths to their private
           configuration directories."""
        Topo.__init__(self)

        # Directory where this file / script is located"
        selfPath = os.path.dirname(os.path.abspath(
            inspect.getfile(inspect.currentframe())))  # script directory

        # Initialize a service helper for Quagga with default options
        quaggaSvc = QuaggaService(autoStop=False)

        # Path configurations for mounts
        quaggaBaseConfigPath = selfPath + '/configs/'

        # List of Quagga host configs
        quaggaHosts = []
        # quaggaHosts.append(QuaggaHost(name='S1', ip='192.168.1.2/24',
        #                               loIP='127.0.0.1', mac = 'aa:aa:aa:aa:aa:aa'))
        # quaggaHosts.append(QuaggaHost(name='CA', ip='192.168.1.1/26',
        #                               loIP='127.0.0.1', mac = 'bb:bb:bb:bb:bb:bb'))
        # quaggaHosts.append(QuaggaHost(name='H2', ip='192.168.1.64/26',
        #                               loIP='127.0.0.1', mac = 'cc:cc:cc:cc:cc:cc'))
        # quaggaHosts.append(QuaggaHost(name='Target', ip='192.168.1.128/26',
        #                               loIP='127.0.0.1', mac = 'dd:dd:dd:dd:dd:dd'))
        # quaggaHosts.append(QuaggaHost(name='H4', ip='192.168.1.192/26',
        #                               loIP='127.0.0.1', mac = 'ee:ee:ee:ee:ee:ee'))

        quaggaHosts.append(QuaggaHost(name='S1', ip='192.168.1.2/24',
                                      loIP='127.0.0.1', mac = 'aa:aa:aa:aa:aa:aa'))
        quaggaHosts.append(QuaggaHost(name='CA', ip='192.168.1.1/24',
                                      loIP='127.0.0.1', mac = 'bb:bb:bb:bb:bb:bb'))
        quaggaHosts.append(QuaggaHost(name='Victim', ip='192.168.1.64/24',
                                      loIP='127.0.0.1', mac = 'cc:cc:cc:cc:cc:cc'))
        quaggaHosts.append(QuaggaHost(name='Target', ip='192.168.1.128/24',
                                      loIP='127.0.0.1', mac = 'dd:dd:dd:dd:dd:dd'))
        quaggaHosts.append(QuaggaHost(name='Attacker', ip='192.168.1.192/24',
                                      loIP='127.0.0.1', mac = 'ee:ee:ee:ee:ee:ee'))

        hostDict = dict()

        # Setup each Quagga router, add a link between it
        for host in quaggaHosts:

            if host.name == 'S1':
              # Create an instance of a host, called a quaggaContainer
              quaggaContainer = self.addSwitch(name=host.name,
                                           ip=host.ip,
                                           mac=host.mac,
                                           hostname=host.name,
                                           privateLogDir=True,
                                           privateRunDir=True,
                                           inMountNamespace=True,
                                           inPIDNamespace=True,
                                           inUTSNamespace=True)
            else:
              # Create an instance of a host, called a quaggaContainer
              quaggaContainer = self.addHost(name=host.name,
                                             ip=host.ip,
                                             mac=host.mac,
                                             hostname=host.name,
                                             privateLogDir=True,
                                             privateRunDir=True,
                                             inMountNamespace=True,
                                             inPIDNamespace=True,
                                             inUTSNamespace=True)

            hostDict[host.name] = quaggaContainer

            # Add a loopback interface with an IP in router's announced range
            self.addNodeLoopbackIntf(node=host.name, ip=host.loIP)

            # Configure and setup the Quagga service for this node
            quaggaSvcConfig = \
                {'quaggaConfigPath': quaggaBaseConfigPath + host.name}
            self.addNodeService(node=host.name, service=quaggaSvc,
                                nodeConfig=quaggaSvcConfig)

        # CA <-> S1
        self.addLink(hostDict["S1"], hostDict["CA"])
        # R1 <-> Victim
        self.addLink(hostDict["S1"], hostDict["Victim"])
        # S1 <-> Target
        self.addLink(hostDict["S1"], hostDict["Target"])
        # S1 <-> Attacker
        self.addLink(hostDict["S1"], hostDict["Attacker"])
