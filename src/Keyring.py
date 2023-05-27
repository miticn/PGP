from Key import PublicKeyWrapper, PrivateKeyWrapper
from AsymmetricCipher import *
from datetime import datetime
from Crypto.PublicKey import RSA
import pickle

class KeyringPU:
    def __init__(self):
        self.keys = []

class KeyringPR:
    def __init__(self):
        self.keys = []

# TODO (Won't serialize it without explicity defining PrivateKeyWrapper here. TODO: Fix this)
class PrivateKeyWrapper:
    def __init__(self, timestamp, rsa_key, name, email, cipher):
        self.timestamp = timestamp
        self.rsa_key = rsa_key
        self.name = name
        self.email = email
        self.cipher = cipher

    def __getstate__(self):
        state = self.__dict__.copy()
        del state['rsa_key']  # Exclude rsa_key from serialization
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self.rsa_key = None  # Set rsa_key to None during deserialization

# Create an instance of KeyringPR
keyring = KeyringPR()

# Example 1
timestamp1 = datetime.now()
rsa_key1 = RSA.generate(1024)
key1 = PrivateKeyWrapper(timestamp1, rsa_key1, "Pera", "example1@example.com", RSACipher())
keyring.keys.append(key1)

# Example 2
timestamp2 = datetime.now()
rsa_key2 = RSA.generate(1024)
key2 = PrivateKeyWrapper(timestamp2, rsa_key2, "Zika", "example2@example.com", RSACipher())
keyring.keys.append(key2)

# Example 3
timestamp3 = datetime.now()
rsa_key3 = RSA.generate(1024)
key3 = PrivateKeyWrapper(timestamp3, rsa_key3, "Mika", "example3@example.com", RSACipher())
keyring.keys.append(key3)

# Example 4
timestamp4 = datetime.now()
rsa_key4 = RSA.generate(1024)
key4 = PrivateKeyWrapper(timestamp4, rsa_key4, "Laza", "example4@example.com", RSACipher())
keyring.keys.append(key4)

# Serialize and store each instance in self.keys using pickle
serialized_keys = []
for key in keyring.keys:
    serialized_key = pickle.dumps(key)
    serialized_keys.append(serialized_key)

# Assign the serialized keys back to self.keys
keyring.keys = serialized_keys

for key in keyring.keys:
    print(key)
    print("\n")

# Deserialize a serialized key from self.keys
deserialized_key = pickle.loads(keyring.keys[0])

print(deserialized_key)