from AsymmetricCipher import *
from datetime import datetime

class PublicKeyWrapper():
    def __init__(self, timestamp : datetime, publicKey : object , name: str, email: str, algorithm: AsymmetricCipher):
        self.timestamp = timestamp
        self.publicKey = publicKey
        self.name = name
        self.email = email
        self.algorithm = algorithm
        self.size = publicKey.size_in_bits()

    def encrypt(self, plaintext):
        print(self.algorithm)
        return self.algorithm.encrypt(plaintext, self.publicKey)

    def verify(self, hash, signature):
        return self.algorithm.verify(hash, signature, self.publicKey)
    
    def getKeyId(self):
        return self.publicKey.public_key().exportKey("DER")[:8]
    
    def getKeyIdHexString(self):
        return self.getKeyId().hex().upper()
    
    def getAlgorithmCode(self):
        return self.algorithm.getAlgorithmCode()
    
    def __getstate__(self):
        state = self.__dict__.copy()
        # Remove any non-picklable attributes
        
        state['publicKey'] = state['publicKey'].export_key()
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        # Restore the non-picklable attribute
        self.publicKey = RSA.import_key(state['publicKey'])

class PrivateKeyWrapper(PublicKeyWrapper):

    def decrypt(self, ciphertext):
        return self.algorithm.decrypt(ciphertext, self.publicKey)

    def sign(self, hash):
        return self.algorithm.sign(hash, self.publicKey)