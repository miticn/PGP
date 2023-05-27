import base64
import time
import zlib
from Keyring import KeyringPR 

import copy

from Crypto.PublicKey import RSA, ElGamal, DSA
from AsymmetricCipher import RSACipher, codeToAsymmetricCipher
from SymmetricCipher import AESCipher, TripleDES, codeToSymmetricCipher
from Key import PrivateKeyWrapper
from hash import SHA1Wrapper

class Message():
    message = None
    filename = None
    timestamp = None

    loadedBytes = None
    verificationBundle = None

    def __init__(self, arg1:bytes, arg2 : bytes = None):
        if arg2 is None:
            self.__initLoadMsg__(arg1)
        else:
            self.__initNewMSG__(arg1, arg2)

    def __initNewMSG__(self,filename: bytes, message: bytes):
        self.message = message
        self.filename = filename
        timestamp = int(time.time())
        self.timestamp = timestamp.to_bytes(4, byteorder='big')#4bytes
    
    def __initLoadMsg__(self, loadedBytes: bytes):
        self.loadedBytes = loadedBytes
        self.__loadMessage()

    def __loadMessage(self):
        if self.loadedBytes is None:
            return
        if False:
            self.loadedBytes = self.radix64Decode(self.loadedBytes)
        if False:
            self.loadedBytes = self.decompressMessage(self.loadedBytes)
        if False:
            pass 
        if self.loadedBytes[0:6] == b'signed':
            self.verificationBundle = copy.deepcopy(self.loadedBytes)
            signatureLength = self.loadedBytes[21:23]
            signatureLength = int.from_bytes(signatureLength, byteorder='big')
            self.loadedBytes = self.loadedBytes[23+signatureLength:]



        self.filename = self.loadedBytes.split(b'\0')[0]
        self.loadedBytes = self.loadedBytes[len(self.filename)+1:]
        self.timestamp = self.loadedBytes[:4]
        self.message = self.loadedBytes[4:]
        self.loadedBytes = None

    def createOuputBytes(self, signed=False, encrypted=False, zipped=False, base64=False,senderKey=None, receiverKey=None):
        self.loadedBytes = self.filename+b'\0'+ self.timestamp + self.message
        if signed:
            self.loadedBytes = self.signMessage(self.loadedBytes, senderKey)
        if encrypted:
            pass
        if zipped:
            self.loadedBytes = self.compressMessage(self.loadedBytes)
        if base64:
            self.loadedBytes = self.radix64Encode(self.loadedBytes)
        return self.loadedBytes


    def signMessage(self, message, key):
        timestamp = int(time.time())
        timestamp = timestamp.to_bytes(4, byteorder='big')#4bytes
        
        hash = SHA1Wrapper().getHash(message)
        signature = key.sign(hash)
        signatureLength = len(signature).to_bytes(2, byteorder='big')
        hash = SHA1Wrapper().getHashBytes(message)
        keyid = key.getKeyId()
        return b'signed'+key.getAlgorithmCode()+timestamp+keyid+hash[0:2]+signatureLength+signature + message
    
    def verifyMessage(self, keyRing):
        algo = self.verificationBundle[6].to_bytes(1, byteorder='big')
        if self.verificationBundle[0:6] != b'signed' or algo not in codeToAsymmetricCipher:
            return False, None
        timestamp = self.verificationBundle[7:11]
        keyid = self.verificationBundle[11:19]
        key = keyRing.getKeyById(keyid)
        if key is None or key.getAlgorithmCode() != algo:
            return False, None
        hashOctets = self.verificationBundle[19:21]#find way to use this to avoid hashing if bad message
        signatureLength = self.verificationBundle[21:23]
        signatureLength = int.from_bytes(signatureLength, byteorder='big')
        signature = self.verificationBundle[23:23+signatureLength]
        messageBundle = self.verificationBundle[23+signatureLength:]
        hash = SHA1Wrapper().getHash(messageBundle)
        return key.verify(hash, signature), key

    def compressMessage(self, message):
        return zlib.compress(message)
    
    def decompressMessage(self, message):
        return zlib.decompress(message)
    
    def radix64Encode(self, message):
        return base64.b64encode(message).decode('ascii')
    
    def radix64Decode(self, message):
        return base64.b64decode(message)
    

if __name__ == "__main__":
    rsa_key = RSA.generate(1024)
    
    private_key = PrivateKeyWrapper(time.time(), rsa_key, "name", "email", RSACipher())
    msg = Message(b"hello", b"Lorem impsum blah blah blah")
    out_mst = msg.createOuputBytes(signed=True, senderKey=private_key)
    print(out_mst)
    msg2 = Message(out_mst)
    print("TEST")
    print(msg2.filename)
    print(msg2.timestamp)
    print(msg2.message)
    keyRing = KeyringPR()
    keyRing.addKey(private_key)
    print("Verify MSG: ",msg2.verifyMessage(keyRing))