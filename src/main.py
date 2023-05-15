from Key import PublicKeyWrapper
from AsymmetricCipher import *
from datetime import datetime
def main():
    timestamp = datetime.now()
    key = PublicKeyWrapper(timestamp, 123, 123 , "Peter", "example@example.com", RSA, 1024)
    print(key.timestamp)

if __name__ == "__main__":
    main()
