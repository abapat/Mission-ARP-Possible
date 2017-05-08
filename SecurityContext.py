import Crypto.Hash.SHA256 as SHA256
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5

'''
Class for handling all symmetric encryption/decrytion and public/private key functionality

Supports generating keys, encrypting and decrypting strings
'''


class SymmetricCrypto:
    '''
        A fernet key is an optional param. Use the generatekey function of this class or just pass nothing
         to have a key generated for you.
    '''
    def __init__(self, key=None):
        self.key = self.generateKey() if key is None else key
        self.suite = Fernet(self.key)

    def encrypt(self, message):
        return self.suite.encrypt(message)

    def decrypt(self, payload):
        return self.suite.decrypt(payload)

    @staticmethod
    def generateKey():
        return Fernet.generate_key()


'''
Class for handling all asymettric encryption/decrytion and public/private key functionality

Supports generating keys, encrypting and decrypting strings
'''


class AsymmetricCrypto:

    RSAKEYLENGTH = 2048

    '''
        PublicKey and Privatekey should be byte data. Pass both or none at all.
    '''
    def __init__(self, publicKey=None, privateKey=None):
        if publicKey is not None and privateKey is not None:
            self.publicKey = RSA.importKey(publicKey)
            self.privateKey = RSA.importKey(privateKey)
        else:
            key = RSA.generate(self.RSAKEYLENGTH)
            self.publicKey = key.publickey()
            self.privateKey = key

        self.encryptionCipher = PKCS1_OAEP.new(self.privateKey)
        self.sigCipher = PKCS1_v1_5.new(self.privateKey)

    '''
        pubkey should be the raw bytes of the public key of the receiver of this secret message.
    '''
    def encrypt(self, publicKeyBytes, message):
        pubKey = RSA.importKey(publicKeyBytes)
        cipher = PKCS1_OAEP.new(pubKey)
        return cipher.encrypt(message)

    '''
        Here we assume we want to decrypt with this objects Private Key.
    '''
    def decrypt(self, ciphertext):
        return self.encryptionCipher.decrypt(ciphertext)

    def sign(self, message):
        hasher = SHA256.new()
        hasher.update(message)
        return self.sigCipher.sign(hasher)

    def verify(self, data, sig, publicKeyBytes):
        pubKey = RSA.importKey(publicKeyBytes)
        signer = PKCS1_v1_5.new(pubKey)
        digest = SHA256.new()
        digest.update(data)
        return signer.verify(digest, sig)

'''
    Simple test for encrypting and decrypting a string
'''

SECURITY = AsymmetricCrypto()


def main():
    payload = SECURITY.sign("Attack at Dawn.")
    print SECURITY.verify("Attack at Dawn.", payload, SECURITY.publicKey.exportKey('DER'))

if __name__ == '__main__':
    main()
