from AsymmetricCipher import *
from datetime import datetime
from SymmetricCipher import AESGCipher
class PublicKeyWrapper():
    def __init__(self, timestamp : datetime, publicKey : object , name: str, email: str, algorithm: AsymmetricCipher):
        self.timestamp = timestamp
        self.keyId = publicKey.public_key().exportKey("DER")[:8]
        self.publicKey = publicKey
        self.name = name
        self.email = email
        self.algorithm = algorithm
        self.size = publicKey.size_in_bits()

    def encrypt(self, plaintext):
        return self.algorithm.encrypt(plaintext, self.publicKey)

    def verify(self, hash, signature):
        return self.algorithm.verify(hash, signature, self.publicKey)
    
    def getKeyId(self):
        return self.keyId
    
    def getKeyIdHexString(self):
        return self.keyId.hex().upper()
    
    def getAlgorithmCode(self):
        return self.algorithm.getAlgorithmCode()
    
    def _importPrivateKey(self, key):
        if self.algorithm.getAlgorithmCode() == RSACipher.getAlgorithmCode():
            return RSA.import_key(key)
        elif self.algorithm.getAlgorithmCode() == ElGamalDSACipher.getAlgorithmCode():
            pass
    

    def __getstate__(self):
        state = self.__dict__.copy()
        # Remove any non-picklable attributes
        
        state['publicKey'] = state['publicKey'].export_key()
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        # Restore the non-picklable attribute
        self.publicKey = self._importPrivateKey(state['publicKey'])

    def exportPublicKeyPem(self):
        return self.publicKey.export_key("PEM")
    
    def exportPublicKeyToFile(self, filename):
        with open(filename, "wb") as f:
            f.write(self.exportPublicKeyPem())
            return True
        return False


class PrivateKeyWrapper(PublicKeyWrapper):
    def __init__(self, timestamp : datetime, privateKey : object , name: str, email: str, algorithm: AsymmetricCipher, password: bytes):
        publicKey = privateKey.public_key()
        super().__init__(timestamp, publicKey, name, email, algorithm)
        self.privateKey = privateKey
        self.privateKey = self.__encryptPrivateKey(password)

    
    def __decryptPrivateKey(self, password):
        key = AESGCipher.decryptWithPassword(password, self.privateKey)
        if key!=None:
            return PublicKeyWrapper._importPrivateKey(self,key)
        return None

    def __encryptPrivateKey(self, password):
        return AESGCipher.encryptWithPassword(password, self.privateKey.export_key())


    # private key must have
    def decrypt(self, ciphertext, password):
        data = None
        privateKey = self.__decryptPrivateKey(password)
        if privateKey is not None:
            data = self.algorithm.decrypt(ciphertext, privateKey)
        return data

    def sign(self, hash, password):
        data = None
        privateKey = self.__decryptPrivateKey(password)
        if privateKey is not None:
            data = self.algorithm.sign(hash, privateKey)
        return data
    
    def exportPrivateKeyPem(self, password):
        data = None
        privateKey = self.__decryptPrivateKey(password)
        if privateKey is not None:
            data = privateKey.export_key("PEM", pkcs=8, protection="scryptAndAES128-CBC", passphrase=password)
        return data
    
    def exportPrivateKeyToFile(self, filename, password):
        data = self.exportPrivateKeyPem(password)
        if data != None:
            with open(filename, "wb") as f:
                f.write(self.exportPrivateKeyPem(password))
                return True
        return False
