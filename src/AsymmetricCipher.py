from abc import ABC, abstractmethod
from Crypto.PublicKey import RSA
from Crypto.PublicKey import DSA
from Crypto.PublicKey import ElGamal

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Signature import DSS

from hash import SHA1Wrapper

class AsymmetricCipher(ABC):

    @abstractmethod
    def encrypt(self, plaintext, public_key):
        pass

    @abstractmethod
    def verify(self, hash, signature, public_key):
        pass

    @abstractmethod
    def decrypt(self, ciphertext, private_key):
        pass

    @abstractmethod
    def sign(self, hash, private_key):
        pass

    @abstractmethod
    def getAlgorithmCode(self):
        pass

    @abstractmethod
    def verifyTwoOctets(self, octets, signature, public_key):
        pass

class RSACipher(AsymmetricCipher):

    @staticmethod
    def encrypt(plaintext, public_key):
        cipher = PKCS1_OAEP.new(public_key)
        return cipher.encrypt(plaintext)

    @staticmethod
    def verify(hash, signature, public_key):
        try:
            return PKCS1_v1_5.new(public_key).verify(hash, signature)
        except (ValueError, TypeError):
            return False

    @staticmethod
    def decrypt(ciphertext, private_key):
        cipher = PKCS1_OAEP.new(private_key)
        return cipher.decrypt(ciphertext)

    @staticmethod
    def sign(hash, private_key):
        signature = PKCS1_v1_5.new(private_key).sign(hash)
        return signature
    
    @staticmethod
    def getAlgorithmCode():
        return b'\x01'
    
    @staticmethod
    def verifyTwoOctets(octets, signature, public_key):
        #verify that the first two octets are same as the first two octets of the hash
        octets = octets[:2]
        #get hash from signature??????????????????????????????????????????????????????????????????????????
        return octets == hash
    
    
class ElGamalDSAKey:
    def __init__(self, ElgamalKey : object, DSAKey : object):
        self.ElgamalKey = ElgamalKey
        self.DSAKey = DSAKey

class ElGamalDSACipher(AsymmetricCipher):
    #DSA is for signing and verification only
    #ElGamal is for encryption and decryption only
    @staticmethod
    def encrypt(plaintext, public_key):#ElGamal
        pass

    @staticmethod
    def verify(hash, signature, public_key):#DSA
        verifier = DSS.new(public_key.DSAKey, 'fips-186-3')
        try:
            verifier.verify(hash, signature)
            return True
        except ValueError:
            return False

    @staticmethod
    def decrypt(ciphertext, private_key):#ElGamal
        pass

    @staticmethod
    def sign(hash, private_key):#DSA
        signer = DSS.new(private_key.DSAKey, 'fips-186-3')
        return signer.sign(hash)
    
    @staticmethod
    def getAlgorithmCode():
        return b'\x02'
    
    @staticmethod
    def verifyTwoOctets(octets, signature, public_key):#DSA
        pass



codeToAsymmetricCipher = {b'\x01': RSACipher(), b'\x02': ElGamalDSACipher()}



#tests for ElGamalDSA

DSAKey = DSA.generate(1024)
key = ElGamalDSAKey(None, DSAKey)

ct = ElGamalDSACipher.encrypt(b"plaintext", key)
print(ElGamalDSACipher.decrypt(ct, key))

txt = b"TESTETSTEST"
hash = SHA1Wrapper.getHash(txt)
signature = ElGamalDSACipher.sign(hash, key)
print(ElGamalDSACipher.verify(hash, signature, key))
#modify signature
signature = signature[:-1] + b'\x00'
print(ElGamalDSACipher.verify(hash, signature, key))






