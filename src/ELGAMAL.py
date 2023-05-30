from Crypto.PublicKey import ElGamal
from Crypto import Random
from Crypto.Util import asn1
import base64
from SymmetricCipher import AESGCipher


class ElGamalHelper:

    def export_key(key, passphrase=None):
        seq = asn1.DerSequence()
        if key.has_private():
            seq[:] = [ key.p, key.g, key.y, key.x ]
        else:
            seq[:] = [ key.p, key.g, key.y ]
        der = seq.encode()

        if not(key.has_private()) and passphrase:
            return "Error: Cannot encrypt a public key!"

        if passphrase:
            der = AESGCipher.encryptWithPassword(passphrase, der)
        
        pem_data = base64.encodebytes(der).decode('ascii')

        if key.has_private() and passphrase:
            pem_data = f"-----BEGIN ENCRYPTED PRIVATE KEY-----\n{pem_data}-----END ENCRYPTED PRIVATE KEY-----\n"
        elif key.has_private():
            pem_data = f"-----BEGIN ELGAMAL PRIVATE KEY-----\n{pem_data}-----END ELGAMAL PRIVATE KEY-----\n"
        else:
            pem_data = f"-----BEGIN ELGAMAL PUBLIC KEY-----\n{pem_data}-----END ELGAMAL PUBLIC KEY-----\n"

        return bytes(pem_data, 'ascii')

    def import_key(pem_data, passphrase=None):
        pem_data = pem_data.decode('ascii')
        pem_data = pem_data.strip().split('\n')[1:-1]
        pem_data = ''.join(pem_data).encode('ascii')

        der = base64.decodebytes(pem_data)

        if passphrase and pem_data.startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----'):
            der = AESGCipher.decryptWithPassword(passphrase, der)
            if der is None:
                return "Error: Wrong passphrase!"

        seq = asn1.DerSequence()
        seq.decode(der)

        if len(seq) == 3:
            key = ElGamal.construct((seq[0], seq[1], seq[2]))
        else:
            key = ElGamal.construct((seq[0], seq[1], seq[2], seq[3]))
        return key