from AsymmetricCipher import AsymmetricCipher
from datetime import datetime

class PublicKeyWrapper():
    def __init__(self, timestamp : datetime, keyId, publicKey , name: str, email: str, algorithm: AsymmetricCipher, size: int):
        self.timestamp = timestamp
        self.keyId = keyId
        self.publicKey = publicKey
        self.name = name
        self.email = email
        self.algorithm = algorithm
        self.size = size

    
    