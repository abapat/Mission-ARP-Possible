"""
Example topology of Quagga routers
"""

import inspect
import os
from mininext.topo import Topo
from mininext.services.quagga import QuaggaService

from collections import namedtuple

QuaggaHost = namedtuple("QuaggaHost", "name ip loIP")
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
        quaggaHosts.append(QuaggaHost(name='R1', ip='192.168.1.2/24',
                                      loIP='127.0.0.1', mac = 'aa:aa:aa:aa:aa:aa'))
        quaggaHosts.append(QuaggaHost(name='H1', ip='192.168.1.1/26',
                                      loIP='127.0.0.1', mac = 'bb:bb:bb:bb:bb:bb'))
        quaggaHosts.append(QuaggaHost(name='H2', ip='192.168.1.64/26',
                                      loIP='127.0.0.1', mac = 'cc:cc:cc:cc:cc:cc'))
        quaggaHosts.append(QuaggaHost(name='H3', ip='192.168.1.128/26',
                                      loIP='127.0.0.1', mac = 'dd:dd:dd:dd:dd:dd'))
        quaggaHosts.append(QuaggaHost(name='H4', ip='192.168.1.192/26',
                                      loIP='127.0.0.1', mac = 'ee:ee:ee:ee:ee:ee'))

        hostDict = dict()

        # Setup each Quagga router, add a link between it
        for host in quaggaHosts:

            # Create an instance of a host, called a quaggaContainer
            quaggaContainer = self.addHost(name=host.name,
                                           ip=host.ip,
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

        # H1 <-> R1
        self.addLink(hostDict["R1"], hostDict["H1"])
        # R1 <-> H2
        self.addLink(hostDict["R1"], hostDict["H2"])
        # R1 <-> H3
        self.addLink(hostDict["R1"], hostDict["H3"])
        # R1 <-> H4
        self.addLink(hostDict["R1"], hostDict["H4"])
