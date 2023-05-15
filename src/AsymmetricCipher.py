from abc import ABC, abstractmethod

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

class RSA(AsymmetricCipher):

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

class ElGamalDSA(AsymmetricCipher):

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