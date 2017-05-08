'''
Class for managing keys

Supports add, deleting, and updating keys
'''

class KeyManager:
    def __init__(self, key_map = dict()):
        self.table = key_map

    def add(self, ip, key):
        self.table[ip] = key

    def update(self, new_table):
        for k, v in new_table.items():
            self.table[k] = v

    def delete(self, ip):
        del self.table[ip]

    def get(self, ip):
        return self.table[ip]

    def __str__(self):
        return str(self.table)
