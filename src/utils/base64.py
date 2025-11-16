import base64
from cryptography.hazmat.primitives import serialization

def b64(obj):
    """Return base64 string from bytes or public key object."""
    if hasattr(obj, "public_bytes"):  # handle public key
        obj = obj.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    elif not isinstance(obj, (bytes, bytearray)):
        raise TypeError(f"b64() expected bytes or public key, got {type(obj)}")
    return base64.b64encode(obj).decode("utf-8")