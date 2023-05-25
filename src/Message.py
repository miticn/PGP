import base64
import time
import zlib

from Crypto.PublicKey import RSA, ElGamal, DSA
from AsymmetricCipher import RSACipher
from Key import PrivateKeyWrapper
from hash import SHA1Wrapper

class Message():
    def __init__(self):
        pass

    def signMessage(self, message, key):
        timestamp = time.time()
        timestamp = bytes(str(timestamp), "utf-8")
        print(timestamp)
        filename = bytes("filename", "utf-8")
        message = filename+ timestamp + message
        hash = SHA1Wrapper().getHash(message)
        signature = key.sign(hash)
        hash = SHA1Wrapper().getHashBytes(message)
        keyid = key.getKeyId()
        return timestamp+keyid+hash[0:2]+signature + message
    
    def verifyMessage(self, message, key):
        pass

    def compressMessage(self, message):
        return zlib.compress(message)
    
    def decompressMessage(self, message):
        return zlib.decompress(message)
    
    def radix64Encode(self, message):
        return base64.b64encode(message).decode('utf-8')
    
    def radix64Decode(self, message):
        return base64.b64decode(message)
    

if __name__ == "__main__":
    message = Message()
    rsa_key = RSA.generate(1024)
    
    private_key = PrivateKeyWrapper(time.time(), rsa_key, "name", "email", RSACipher())
    print(private_key.getKeyId())
    print(private_key.getKeyIdHexString())
    msg = message.signMessage(b"hello", private_key)
    compressed = message.compressMessage(msg)
    base64_message = message.radix64Encode(compressed)
    print(base64_message)
    print(message.radix64Decode(base64_message))
    print(compressed)