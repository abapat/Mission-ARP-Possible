'''
Class for managing keys

Supports add, deleting, and updating keys
'''

class KeyManager:
    def __init__(self):
        self.table = dict()

    def add(self, ip, key):
        self.table[ip] = key

    def update(self, ip, key):
        self.table[ip] = key

    def delete(self, ip):
        del self.table[ip]

    def get(self, ip):
        return self.table[ip]

    def __str__(self):
        return str(self.table)
