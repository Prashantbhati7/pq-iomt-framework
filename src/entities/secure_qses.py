"""QSES with an encrypted sensor link.

Adds, on top of the paper's QSES:
  - its own ML-KEM-512 pair (pk_kem / sk_kem) for the sensor handshake
  - the handshake responder (offer_session / finish_session)
  - receive_from_sensor(): decrypt with the session key, then run the
    unchanged Algorithm 2 (process_and_forward)
"""
import os

from cryptography.exceptions import InvalidTag

from src.crypto.hashing import sha3_256
from src.crypto.kdf import derive_aes_key
from src.crypto.kem import KEMKeyPair
from src.crypto.signature import verify
from src.crypto.symmetric import AESGCMCipher
from src.entities.qses import QSESNode
from src.protocol.errors import ProtocolError
from src.protocol.secure_messages import (
    NONCE_SIZE, SESSION_INFO, SensorLinkPacket, finish_bytes, offer_bytes,
)


class SecureQSESNode(QSESNode):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._kem = KEMKeyPair()      # (pk_kem, sk_kem): for the sensor link only
        self.sessions = {}            # session_id -> AESGCMCipher (the session key K)
        self._pending = {}            # client_id -> (n_i, n_q, session_id)

    # ---- handshake -----------------------------------------------------

    def offer_session(self, client_id: int, n_i: bytes):
        """Step 2: reply with (pk_kem, n_q, session_id, sigma_Q)."""
        if client_id not in self.client_registry:
            raise ProtocolError(f"unknown client {client_id}")
        n_q = os.urandom(NONCE_SIZE)
        session_id = int.from_bytes(os.urandom(4), "big")
        self._pending[client_id] = (n_i, n_q, session_id)
        offer = offer_bytes(client_id, n_i, n_q, session_id, self._kem.public_key)
        return self._kem.public_key, n_q, session_id, self._signer.sign(sha3_256(offer))

    def finish_session(self, client_id: int, ct: bytes, sig_d: bytes) -> int:
        """Step 5: verify sigma_D, run Decaps, derive K."""
        pending = self._pending.pop(client_id, None)   # single use: no replay of FINISH
        if pending is None:
            raise ProtocolError("no handshake in progress for this client")
        n_i, n_q, session_id = pending

        finish = finish_bytes(client_id, n_i, n_q, session_id, ct)
        if not verify(sha3_256(finish), sig_d, self.client_registry[client_id]):
            raise ProtocolError("invalid handshake signature")

        ss = self._kem.decapsulate(ct)
        key = derive_aes_key(ss, n_i + n_q, info=SESSION_INFO)
        self.sessions[session_id] = AESGCMCipher(key)
        return session_id

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

    def close(self):
        self._kem.close()
        super().close()