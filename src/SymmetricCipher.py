from abc import ABC, abstractmethod
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
import os

class SymmetricCipher(ABC):
    @abstractmethod
    def encrypt(self, key, plaintext):
        pass

    @abstractmethod
    def decrypt(self, key, ciphertext):
        pass


class AES128(SymmetricCipher):
    @staticmethod
    def encrypt(key, plaintext):
        backend = default_backend()
        iv = os.urandom(16)
        padder = PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        return iv + ciphertext

    @staticmethod
    def decrypt(key, ciphertext):
        backend = default_backend()
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext

class TripleDES(SymmetricCipher):
    @staticmethod
    def encrypt(key, plaintext):
        backend = default_backend()
        iv = os.urandom(8)
        padder = PKCS7(64).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return iv + ciphertext

    @staticmethod
    def decrypt(key, ciphertext):
        backend = default_backend()
        iv = ciphertext[:8]
        ciphertext = ciphertext[8:]
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = PKCS7(64).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext

'''
key = os.urandom(16)
plaintext = b"hello world hello world hello world"
print("Plaintext:",plaintext)
ciphertext = AES128.encrypt(key, plaintext)
print("Ciphertext AES128:", ciphertext)
decrypted_text = AES128.decrypt(key, ciphertext)
print("Decrypted text:", decrypted_text)

ciphertext = TripleDES.encrypt(key, plaintext)
print("Ciphertext TripleDES:", ciphertext)
decrypted_text = TripleDES.decrypt(key, ciphertext)
print("Decrypted text:", decrypted_text)
'''
