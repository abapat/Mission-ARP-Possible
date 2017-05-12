# Mission ARP-Possible

A protocol for securing the ARP protocol with asymmetric key cryptography

## Collaborators

Amit Bapat
Varun Sayal
Leixiang Wu

## Installation and Running

## Design

To prevent ARP spoofing, we will use digital signatures to ensure only valid hosts have
entries in the ARP table; this will prevent poisoning. Each host on the network will have a
public/private key (RSA 2048 bit) associated with it’s IP address. There will be a Certificate
Authority (CA) on the network that will need to be set up by a network administrator. The CA
will hold the mapping of all IP addresses to their public keys. Furthermore, each host on the
network will have knowledge of their public and private keys. For our protocol to work, we rely
on 2 assumptions:
1. Every host who joins the network will create a public/private key pair and inform the
DHCP server of its public key when it receives and IP. This mapping is then relayed to
the CA.
2. Every host who joins the network knows the public key of the certificate authority. This
can also be done using Secure DHCP
We believe (1) is a reasonable assumption because many routers already implement a
way to assign IPs securely, so the host can send its public key in the DHCP request. Assumption
(2) can be accomplished by giving the public key of the CA when the host is assigned an IP.
For implementation purposes, we will run the protocol on application layer. An ARP
packet will be sent as normal, but have a signature appended to it in the payload section of UDP.
The signature will be verified by the host receiving the response, by validating it with the
appropriate public key. The public key is obtained by querying the Certificate Authority and
caching the result in memory. Each host will have the public key of the CA, so they can verify
responses sent by the CA.
    
## Protocol Steps
0. All hosts have a pub/private key and the public key of the CA that can be disseminated
via Secure DHCP. The CA has knowledge of this information. This can happen when
hosts join the network.
1. Host A joins network, and wants to send data to some node on the network. Host A sends
an ARP request for some host’s mac address
2. A reply is received by host A from host B in the network. A signature is attached to the
ARP packet
3. Host A queries the CA for the public key of Host B
4. The CA responds to A with the public key of Host B. A signature is attached to this
message
5. Host A verifies the signature of the message sent by the CA (using the CA’s public key).
Then it verifies the ARP response using the public key of B to ensure it was sent by B. It
then caches the public key of B for later use.
