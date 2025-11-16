import unittest
from cryptography.hazmat.primitives import serialization
from utils.crypto_utils import CryptoUtils
from double_ratchet.double_ratchet import DoubleRatchet


class TestSimpleDoubleRatchet(unittest.TestCase):

    def setUp(self):
        # Generate initial root key
        self.root_key = CryptoUtils.random_bytes(32)
        # Create Alice and Bob DR instances
        self.alice = DoubleRatchet(self.root_key)
        self.bob = DoubleRatchet(self.root_key)

    def test_basic_encrypt_decrypt(self):
        """Alice sends a message, Bob can decrypt"""
        msg = "Hello Bob!"
        packet = self.alice.encrypt(msg)
        # Simulate sending DH pub to Bob
        self.bob.remote_dh = self.alice.my_pub
        decrypted = self.bob.decrypt(packet)
        self.assertEqual(msg, decrypted)

    def test_two_messages_in_order(self):
        """Encrypting two messages in a row works"""
        msg1 = "First"
        msg2 = "Second"
        packet1 = self.alice.encrypt(msg1)
        packet2 = self.alice.encrypt(msg2)

        # Bob updates remote DH for first message
        self.bob.remote_dh = self.alice.my_pub
        dec1 = self.bob.decrypt(packet1)

        # Bob updates remote DH again for second message
        self.bob.remote_dh = self.alice.my_pub
        dec2 = self.bob.decrypt(packet2)

        self.assertEqual(msg1, dec1)
        self.assertEqual(msg2, dec2)

    def test_different_keys_after_ratchet(self):
        """New DH ratchet produces different sending chain keys"""
        old_CKs = self.alice.CKs
        # Simulate Bob sending new DH key to Alice to trigger ratchet
        bob_new_dh_pub = CryptoUtils.generate_key_pair()[1].public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        self.alice.ratchet_step(bob_new_dh_pub)
        self.assertNotEqual(old_CKs, self.alice.CKs)

    def test_root_key_consistency(self):
        """Same root key generates same initial CKs for two users"""
        ck_alice = CryptoUtils.hkdf(self.root_key, info=b'init')
        ck_bob = CryptoUtils.hkdf(self.root_key, info=b'init')
        self.assertEqual(ck_alice, ck_bob)