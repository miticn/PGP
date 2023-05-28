from Key import PublicKeyWrapper, PrivateKeyWrapper
from AsymmetricCipher import *
from datetime import datetime
from Crypto.PublicKey import RSA
import pickle

class KeyringPR:
    def __init__(self):
        self._keys = []

    def addKey(self, key):
        self._keys.append(key)

    def getKeyById(self, keyID):
        for key in self._keys:
            if keyID == key.getKeyId():
                return key
        
        return None
    
    def serialize(self):
        return pickle.dumps(self)
    

class KeyringPU:
    def __init__(self):
        self._keys = []

    def addKey(self, key):
        self._keys.append(key)

    def getKeyById(self, keyID):
        for key in self._keys:
            if keyID == key.getKeyId():
                return key
        
        return None
    
    def serialize(self):
        return pickle.dumps(self)


# Create an instance of KeyringPR
keyring = KeyringPR()

# Example 1
timestamp1 = datetime.now()
rsa_key1 = RSA.generate(1024)
key1 = PrivateKeyWrapper(timestamp1, rsa_key1, "Pera", "example1@example.com", RSACipher())
keyring.addKey(key1)

# Example 2
timestamp2 = datetime.now()
rsa_key2 = RSA.generate(1024)
key2 = PrivateKeyWrapper(timestamp2, rsa_key2, "Zika", "example2@example.com", RSACipher())
keyring.addKey(key2)

# Example 3
timestamp3 = datetime.now()
rsa_key3 = RSA.generate(1024)
key3 = PrivateKeyWrapper(timestamp3, rsa_key3, "Mika", "example3@example.com", RSACipher())
keyring.addKey(key3)

# Example 4
timestamp4 = datetime.now()
rsa_key4 = RSA.generate(1024)
key4 = PrivateKeyWrapper(timestamp4, rsa_key4, "Laza", "example4@example.com", RSACipher())
print(key4.getKeyIdHexString())
keyring.addKey(key4)

keyring_serialized = keyring.serialize()
keyring_deserialized = pickle.loads(keyring_serialized)

print(keyring_deserialized._keys[3].getKeyIdHexString())