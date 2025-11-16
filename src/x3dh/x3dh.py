from utils.crypto_utils import CryptoUtils
import base64
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import serialization
from datetime import datetime

class X3DHProtocol:
    def __init__(self):
        self.utils = CryptoUtils()

    def _decode_x25519_public(self, b64_key):
        raw = base64.b64decode(b64_key)
        return x25519.X25519PublicKey.from_public_bytes(raw)

    def _decode_ed25519_public(self, b64_key):
        raw = base64.b64decode(b64_key)
        return ed25519.Ed25519PublicKey.from_public_bytes(raw)

    def _serialize_public_x25519(self, pub):
        raw = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return base64.b64encode(raw).decode('utf-8')

    def initiate_session(self, initiator_identity_priv, initiator_identity_pub, recipient_bundle):
        """
        Iniciador (Alice) establece una sesión con el receptor (Bob)
        usando el bundle público de Bob.
        """
        # 1. Verificar firma del Signed PreKey de Bob
        spk_pub = self._decode_x25519_public(recipient_bundle['spk'])
        spk_sig = base64.b64decode(recipient_bundle['spk_sig'])
        sign_pub = self._decode_ed25519_public(recipient_bundle['sign_key'])

        sign_pub.verify(
            spk_sig,
            spk_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        )

        # 2. Obtener las otras claves públicas de Bob
        ik_b = self._decode_x25519_public(recipient_bundle['identity_dh'])
        opk_pub = self._decode_x25519_public(recipient_bundle['opk'])

        # 3. Generar clave efímera de Alice
        ek_a_priv, ek_a_pub = CryptoUtils.generate_key_pair()

        # 4. Calcular los 4 DH
        dh1 = CryptoUtils.dh_exchange(initiator_identity_priv, spk_pub)  # IK_A × SPK_B
        dh2 = CryptoUtils.dh_exchange(ek_a_priv, ik_b)                   # EK_A × IK_B
        dh3 = CryptoUtils.dh_exchange(ek_a_priv, spk_pub)    
                    # EK_A × SPK_B
        combined_secret = dh1 + dh2 + dh3
        root_key = self.utils.hkdf(combined_secret, info=b"X3DH_Key")

        # 5. Crear mensaje de inicio
        initiation_message = {
            "ik_a": self._serialize_public_x25519(initiator_identity_pub),
            "ek_a": self._serialize_public_x25519(ek_a_pub),
            "timestamp": datetime.now().isoformat()
        }

        return root_key, initiation_message

    def respond_session(self, responder_keybundle, initiator_message):
        """
        Receptor (Bob) responde a la sesión iniciada por Alice.
        """
        # 1. Extraer claves del receptor
        ik_b_priv = responder_keybundle.identity_priv
        spk_b_priv = responder_keybundle.spk_priv
        opk_b_priv = responder_keybundle.opk_priv

        # 2. Verificar coherencia de firma (defensa adicional)
        responder_keybundle.sign_pub.verify(
            responder_keybundle.spk_sig,
            responder_keybundle.spk_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        )

        # 3. Decodificar las claves públicas del iniciador
        ik_a_pub = self._decode_x25519_public(initiator_message["ik_a"])
        ek_a_pub = self._decode_x25519_public(initiator_message["ek_a"])

        # 4. Calcular los 4 DH (orden espejo)
        dh1 = CryptoUtils.dh_exchange(spk_b_priv, ik_a_pub)   # SPK_B × IK_A
        dh2 = CryptoUtils.dh_exchange(ik_b_priv, ek_a_pub)    # IK_B × EK_A
        dh3 = CryptoUtils.dh_exchange(spk_b_priv, ek_a_pub)
           # SPK_B × EK_A
        combined_secret = dh1 + dh2 + dh3
        root_key = self.utils.hkdf(combined_secret, info=b"X3DH_Key")

        return root_key