from utils.base64 import b64
from x3dh.key_bundle import KeyBundle
import base64
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

def b64decode_str(s):
    return base64.b64decode(s)

def test_keybundle_structure():
    kb = KeyBundle()
    bundle = kb.get_public_bundle()
    expected_fields = ["identity_dh", "sign_key", "spk", "spk_sig", "opk"]
    for field in expected_fields:
        assert field in bundle, f"Missing field: {field}"

def test_base64_validity():
    kb = KeyBundle()
    bundle = kb.get_public_bundle()
    for k, v in bundle.items():
        try:
            b64decode_str(v)
        except Exception:
            raise AssertionError(f"Invalid base64 in {k}")

def test_signature_verification():
    kb = KeyBundle()
    bundle = kb.get_public_bundle()
    sign_pub_bytes = b64decode_str(bundle["sign_key"])
    spk_bytes = b64decode_str(bundle["spk"])
    sig_bytes = b64decode_str(bundle["spk_sig"])

    sign_pub = ed25519.Ed25519PublicKey.from_public_bytes(sign_pub_bytes)

    try:
        sign_pub.verify(sig_bytes, spk_bytes)
    except InvalidSignature:
        raise AssertionError("Invalid signature on signed prekey")

def test_unique_keys():
    kb1 = KeyBundle()
    kb2 = KeyBundle()
    b1 = kb1.get_public_bundle()
    b2 = kb2.get_public_bundle()
    assert b1 != b2, "Two key bundles should not be identical!"

if __name__ == "__main__":
    test_keybundle_structure()
    test_base64_validity()
    test_signature_verification()
    test_unique_keys()
