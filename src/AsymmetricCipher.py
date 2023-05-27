from abc import ABC, abstractmethod
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5



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

class ElGamalDSACipher(AsymmetricCipher):
    #DSA is for signing and verification only
    #ElGamal is for encryption and decryption only
    @staticmethod
    def encrypt(plaintext, public_key):
        pass

    @staticmethod
    def verify(hash, signature, public_key):
        pass

    @staticmethod
    def decrypt(ciphertext, private_key):
        pass

    @staticmethod
    def sign(hash, private_key):
        pass
    
    @staticmethod
    def getAlgorithmCode():
        return b'\x02'
    
    @staticmethod
    def verifyTwoOctets(octets, signature, public_key):
        pass



codeToAsymmetricCipher = {b'\x01': RSACipher(), b'\x02': ElGamalDSACipher()}