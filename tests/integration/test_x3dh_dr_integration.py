import unittest
from x3dh.key_bundle import KeyBundle
from x3dh.x3dh import X3DHProtocol
from double_ratchet.double_ratchet import DoubleRatchet

class TestX3DHDoubleRatchetIntegration(unittest.TestCase):

    def setUp(self):
        # Create key bundles
        self.alice_bundle = KeyBundle()
        self.bob_bundle = KeyBundle()

        # Create X3DH protocol
        self.x3dh = X3DHProtocol()

    def test_integration_chat(self):
        # ----- X3DH handshake -----
        # Alice initiates session
        root_key_a, init_msg = self.x3dh.initiate_session(
            self.alice_bundle.identity_priv,
            self.alice_bundle.identity_pub,
            self.bob_bundle.get_public_bundle()
        )

        # Bob responds
        root_key_b = self.x3dh.respond_session(self.bob_bundle, init_msg)

        # Both root keys should match
        self.assertEqual(root_key_a, root_key_b)
        root_key = root_key_a

        # ----- Initialize Double Ratchets -----
        alice_dr = DoubleRatchet(root_key)
        bob_dr = DoubleRatchet(root_key)

        # First message from Alice → Bob
        message1 = "Hello Bob! 🌟"
        packet1 = alice_dr.encrypt(message1)

        # Simulate sending Alice's DH pub to Bob
        bob_dr.remote_dh = alice_dr.my_pub
        decrypted1 = bob_dr.decrypt(packet1)
        self.assertEqual(message1, decrypted1)

        # Second message from Bob → Alice
        message2 = "Hi Alice! 👋"
        packet2 = bob_dr.encrypt(message2)

        # Simulate sending Bob's DH pub to Alice
        alice_dr.remote_dh = bob_dr.my_pub
        decrypted2 = alice_dr.decrypt(packet2)
        self.assertEqual(message2, decrypted2)

        # Third message Alice → Bob (to test ratcheting)
        message3 = "How are you?"
        packet3 = alice_dr.encrypt(message3)
        bob_dr.remote_dh = alice_dr.my_pub
        decrypted3 = bob_dr.decrypt(packet3)
        self.assertEqual(message3, decrypted3)
