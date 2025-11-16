import base64
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from utils.crypto_utils import CryptoUtils

class DoubleRatchet:
    def __init__(self, root_key, my_dh_pair=None, remote_dh=None):
        self.root_key = root_key
        self.my_priv, self.my_pub = my_dh_pair if my_dh_pair else CryptoUtils.generate_key_pair()
        self.remote_dh = remote_dh
        self.CKs = CryptoUtils.hkdf(root_key, info=b'init')  # chain key de envío
        self.CKr = CryptoUtils.hkdf(root_key, info=b'init')  # chain key de recepción
    def _kdf_chain(self, ck):
        new_ck = CryptoUtils.hkdf(ck, info=b'ck')
        mk = CryptoUtils.hkdf(ck, info=b'mk')
        return new_ck, mk

    def _kdf_root(self, root_key, dh_out):
        new_root = CryptoUtils.hkdf(root_key + dh_out, info=b'rk')
        CKs = CryptoUtils.hkdf(new_root, info=b'ck_s')
        CKr = CryptoUtils.hkdf(new_root, info=b'ck_r')
        return new_root, CKs, CKr

    def ratchet_step(self, remote_pub_bytes):
        self.remote_dh = x25519.X25519PublicKey.from_public_bytes(remote_pub_bytes)

        # 1. Calculate receiving chain
        dh1 = CryptoUtils.dh_exchange(self.my_priv, self.remote_dh)
        self.root_key, _, self.CKr = self._kdf_root(self.root_key, dh1)

        # 2. New DH keypair
        self.my_priv, self.my_pub = CryptoUtils.generate_key_pair()

        # 3. Sending chain
        dh2 = CryptoUtils.dh_exchange(self.my_priv, self.remote_dh)
        self.root_key, self.CKs, _ = self._kdf_root(self.root_key, dh2)

    def encrypt(self, plaintext):
        self.CKs, mk = self._kdf_chain(self.CKs)
        nonce = CryptoUtils.random_bytes(12)
        aesgcm = AESGCM(mk)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "dh_pub": base64.b64encode(
                self.my_pub.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            ).decode()
        }

    def decrypt(self, packet):
        remote_pub_bytes = base64.b64decode(packet["dh_pub"])
        if (self.remote_dh is None or
            self.remote_dh.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ) != remote_pub_bytes):
            self.ratchet_step(remote_pub_bytes)

        self.CKr, mk = self._kdf_chain(self.CKr)
        nonce = base64.b64decode(packet["nonce"])
        ciphertext = base64.b64decode(packet["ciphertext"])
        aesgcm = AESGCM(mk)
        plain = aesgcm.decrypt(nonce, ciphertext, None)
        return plain.decode()