from Key import PublicKeyWrapper, PrivateKeyWrapper
from AsymmetricCipher import *
from datetime import datetime
from Crypto.PublicKey import RSA, ElGamal, DSA

def main():
    timestamp = datetime.now()
    rsa_key = RSA.generate(1024)
    key = PrivateKeyWrapper(timestamp, 123, rsa_key, "Peter", "example@example.com", RSACipher())
    Message = b"Hello World"
    encrypted = key.encrypt(Message)
    print(encrypted)
    print(key.decrypt(encrypted))

    signed = b"s"
    signed = key.sign(Message)
    print(signed)
    print(key.verify(Message, signed))
if __name__ == "__main__":
    main()
