'''
Class for managing ARP table

Supports add, deleting, and updating ARP table entries
'''

class ARPTable:
    def __init__(self):
        self.table = dict()

    def add(self, ip, mac):
    	self.table[ip] = mac

    def update(self, ip, mac):
    	self.table[ip] = mac

    def delete(self, ip):
    	del self.table[ip]

    def __str__(self):
    	return str(self.table)