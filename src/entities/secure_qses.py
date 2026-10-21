"""QSES with an encrypted sensor link.

Adds, on top of the paper's QSES:
  - accept_session(): answer the sensor's handshake. The QSES runs Encaps
    against the sensor's fresh Kyber public key and derives the session key.
  - receive_from_sensor(): decrypt with the session key, then run the
    unchanged Algorithm 2 (process_and_forward)

The QSES holds no Kyber key pair for the sensor link, only the session keys.
"""
import os

from cryptography.exceptions import InvalidTag

from src.crypto.hashing import sha3_256
from src.crypto.kdf import derive_aes_key
from src.crypto.kem import encapsulate
from src.crypto.signature import verify
from src.crypto.symmetric import AESGCMCipher
from src.entities.qses import QSESNode
from src.protocol.errors import ProtocolError
from src.protocol.secure_messages import (
    NONCE_SIZE, SESSION_INFO, SensorLinkPacket, hello_bytes, reply_bytes,
)


class SecureQSESNode(QSESNode):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sessions = {}            # session_id -> AESGCMCipher (the session key K)
        self._seen_n_i = set()        # sensor nonces already used (stops replay of step 1)

    # ---- handshake -----------------------------------------------------

    def accept_session(self, client_id: int, n_i: bytes, pk_kem: bytes, sig_d: bytes):
        """Step 2: verify the sensor's hello, run Encaps, derive K.

        Returns (n_q, session_id, ct, sigma_Q), the reply sent to the sensor.
        """
        pk_client = self.client_registry.get(client_id)
        if pk_client is None:
            raise ProtocolError(f"unknown client {client_id}")
        if not verify(sha3_256(hello_bytes(client_id, n_i, pk_kem)), sig_d, pk_client):
            raise ProtocolError("invalid handshake signature")
        if n_i in self._seen_n_i:
            raise ProtocolError("replayed handshake")
        self._seen_n_i.add(n_i)

        ct, ss = encapsulate(pk_kem)                       # lock a secret with the SENSOR's padlock
        n_q = os.urandom(NONCE_SIZE)
        session_id = int.from_bytes(os.urandom(4), "big")
        key = derive_aes_key(ss, n_i + n_q, info=SESSION_INFO)
        self.sessions[session_id] = AESGCMCipher(key)

        reply = reply_bytes(client_id, n_i, n_q, session_id, ct)
        return n_q, session_id, ct, self._signer.sign(sha3_256(reply))

    # ---- every reading ---------------------------------------------------

    def receive_from_sensor(self, packet):
        """Decrypt the sensor link, then run Algorithm 2 unchanged."""
        if isinstance(packet, (bytes, bytearray)):
            packet = SensorLinkPacket.from_bytes(bytes(packet))

        cipher = self.sessions.get(packet.session_id)
        if cipher is None:
            raise ProtocolError("unknown session")
        try:
            plaintext = cipher.decrypt_detached(
                packet.iv, packet.ciphertext, packet.tag, packet.header())
        except InvalidTag:
            raise ProtocolError("sensor link: AES-GCM authentication failed") from None

        return self.process_and_forward(plaintext)