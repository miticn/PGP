from Key import PublicKeyWrapper, PrivateKeyWrapper
from AsymmetricCipher import *
from datetime import datetime
from Crypto.PublicKey import RSA
import pickle
from SymmetricCipher import AESGCipher

class Keyring:
    def __init__(self, private: bool = False):
        self._keys = []
        self._private = private

    def addKey(self, key):
        self._keys.append(key)

    def getKeyById(self, keyID):
        for key in self._keys:
            if keyID == key.getKeyId():
                return key
        
        return None
    
    def serialize(self):
        return pickle.dumps(self)
    
    @staticmethod
    def deserialize(byts):
        return pickle.loads(byts)
    
    def saveToFile(self, filename, password):
        with open(filename, "wb") as f:
            encrypted_bytes = AESGCipher.encryptWithPassword(password, self.serialize())
            f.write(encrypted_bytes)
    
    @staticmethod
    def loadFromFile(filename, password):
        with open(filename, "rb") as f:
            encrypted_bytes = f.read()
            decrypted_bytes = AESGCipher.decryptWithPassword(password, encrypted_bytes)
            return Keyring.deserialize(decrypted_bytes)



# Create an instance of KeyringPR
keyring = Keyring(True)

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

# Eample for saveToFile and loadFromFile
keyring.saveToFile("keyring.bin", b"123456")
keyring_loaded = Keyring.loadFromFile("keyring.bin", b"123456")
print(keyring_loaded.getKeyById(key4.getKeyId()).getKeyIdHexString())