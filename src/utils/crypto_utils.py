from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

class CryptoUtils:
    @staticmethod
    def generate_key_pair():
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def dh_exchange(private_key, public_key):
        return private_key.exchange(public_key)

    @staticmethod
    def hkdf(ikm, salt=None, info=b'', length=32):
        if salt is None:
            salt = b'\x00' * 32
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
            backend=default_backend()
        )
        return hkdf.derive(ikm) # deriva llave de output DH