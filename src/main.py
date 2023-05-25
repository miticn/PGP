from Key import PublicKeyWrapper, PrivateKeyWrapper
from AsymmetricCipher import *
from datetime import datetime
from Crypto.PublicKey import RSA, ElGamal, DSA
from hash import SHA1Wrapper

def main():
    timestamp = datetime.now()
    rsa_key = RSA.generate(1024)
    key = PrivateKeyWrapper(timestamp, rsa_key, "Peter", "example@example.com", RSACipher())
    Message = b"Hello World"
    encrypted = key.encrypt(Message)
    print(encrypted)
    print(key.decrypt(encrypted))

    sha = SHA1Wrapper()
    hash = sha.getHash(Message)
    signature = key.sign(hash)
    print(signature)
    hash2 = sha.getHash(b"test")
    print(key.verify(hash2, signature))
    print(key.verify(hash, signature))

if __name__ == "__main__":
    main()
