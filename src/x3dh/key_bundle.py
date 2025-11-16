from utils.crypto_utils import CryptoUtils
from utils.base64 import b64
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

class KeyBundle:
    def __init__(self):
        # Identity keys
        self.identity_priv, self.identity_pub = CryptoUtils.generate_key_pair()
        self.sign_priv = ed25519.Ed25519PrivateKey.generate()
        self.sign_pub = self.sign_priv.public_key()

        # Signed prekey
        self.spk_priv, self.spk_pub = CryptoUtils.generate_key_pair()
        self.spk_sig = self.sign_priv.sign(self.spk_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ))

        # One-time prekey
        self.opk_priv, self.opk_pub = CryptoUtils.generate_key_pair()

    def get_public_bundle(self):
        return {
            "identity_dh": b64(self.identity_pub),
            "sign_key": b64(self.sign_pub),
            "spk": b64(self.spk_pub),
            "spk_sig": b64(self.spk_sig),
            "opk": b64(self.opk_pub),
        }