from abc import ABC
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

class Hash(ABC):
    @staticmethod
    def getHash(string):
        pass

class SHA1(Hash):
    @staticmethod
    def getHash(string):
        string = string.encode()
        digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
        digest.update(string)
        return digest.finalize()

'''
s = "Hello, World!"
SHA1 = SHA1()
b = SHA1.getHash(s)

print(b) # returns bytes
'''
