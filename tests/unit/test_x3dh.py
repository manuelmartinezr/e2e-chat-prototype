import base64
from cryptography.hazmat.primitives import serialization
from x3dh.key_bundle import KeyBundle
from x3dh.x3dh import X3DHProtocol


def test_x3dh_shared_key():
    alice = KeyBundle()
    bob = KeyBundle()
    proto = X3DHProtocol()

    root_a, msg = proto.initiate_session(alice.identity_priv, alice.identity_pub, bob.get_public_bundle())
    root_b = proto.respond_session(bob, msg)

    assert root_a == root_b, "Shared root keys do not match!"

def test_signature_verification():
    bob = KeyBundle()
    proto = X3DHProtocol()
    bob_bundle = bob.get_public_bundle()

    # decode keys
    spk_pub = proto._decode_x25519_public(bob_bundle['spk'])
    sig = base64.b64decode(bob_bundle['spk_sig'])
    sign_pub = proto._decode_ed25519_public(bob_bundle['sign_key'])

    # should not raise
    sign_pub.verify(sig, spk_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ))

def test_base64_encoding():
    kb = KeyBundle()
    bundle = kb.get_public_bundle()
    for field in ['identity_dh', 'sign_key', 'spk', 'spk_sig', 'opk']:
        raw = base64.b64decode(bundle[field])  # should not raise
        assert isinstance(raw, bytes)

def test_unique_ephemeral_keys():
    alice = KeyBundle()
    bob = KeyBundle()
    proto = X3DHProtocol()

    _, msg1 = proto.initiate_session(alice.identity_priv, alice.identity_pub, bob.get_public_bundle())
    _, msg2 = proto.initiate_session(alice.identity_priv, alice.identity_pub, bob.get_public_bundle())

    ek1_pub = msg1['ek_a']
    ek2_pub = msg2['ek_a']

    assert ek1_pub != ek2_pub, "Ephemeral keys should differ for each session!"

if __name__ == "__main__":
    test_x3dh_shared_key()
    test_signature_verification()
    test_base64_encoding()
    test_unique_ephemeral_keys()
