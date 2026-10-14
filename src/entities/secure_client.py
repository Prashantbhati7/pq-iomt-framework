"""IoMT device with a per-session AES key shared with the QSES.

Kyber (ML-KEM-512) runs once per session. Every reading after that is signed
exactly as in the paper (Algorithm 1) and then encrypted with AES-256-GCM.
"""
import os
import struct

from src.crypto.hashing import sha3_256
from src.crypto.kdf import derive_aes_key
from src.crypto.kem import encapsulate
from src.crypto.signature import verify
from src.crypto.symmetric import AESGCMCipher
from src.entities.client import ClientNode
from src.protocol.errors import ProtocolError
from src.protocol.secure_messages import (
    NONCE_SIZE, SESSION_INFO, SensorLinkPacket, finish_bytes, offer_bytes,
)


class SecureClientNode(ClientNode):
    def __init__(self, *args, qses_public_key: bytes, **kwargs):
        super().__init__(*args, **kwargs)
        self._qses_public_key = qses_public_key   # pk_QSES, loaded at enrollment
        self._n_i = None
        self._link_cipher = None                  # AES-GCM with the session key K
        self._link_session_id = None

    # ---- handshake (once per session) ----------------------------------

    def begin_session(self):
        """Step 1: sensor -> QSES: (id, n_i)."""
        self._n_i = os.urandom(NONCE_SIZE)
        return self.client_id, self._n_i

    def complete_session(self, pk_kem: bytes, n_q: bytes, session_id: int, sig_q: bytes):
        """Steps 3-4: check the QSES offer, run Encaps, derive K, return (ct, sigma_D)."""
        if self._n_i is None:
            raise ProtocolError("no handshake in progress")
        offer = offer_bytes(self.client_id, self._n_i, n_q, session_id, pk_kem)
        if not verify(sha3_256(offer), sig_q, self._qses_public_key):
            raise ProtocolError("invalid QSES offer signature")

        ct, ss = encapsulate(pk_kem)
        finish = finish_bytes(self.client_id, self._n_i, n_q, session_id, ct)
        sig_d = self._signer.sign(sha3_256(finish))

        key = derive_aes_key(ss, self._n_i + n_q, info=SESSION_INFO)
        self._link_cipher = AESGCMCipher(key)
        self._link_session_id = session_id
        self._n_i = None
        return ct, sig_d

    # ---- every reading ----------------------------------------------------

    def create_encrypted_reading(self, telemetry: bytes) -> SensorLinkPacket:
        """Algorithm 1 (sign), then AES-GCM over the whole packet with K."""
        if self._link_cipher is None:
            raise ProtocolError("no session: run the handshake first")
        packet = self.create_signed_reading(telemetry)
        sid = self._link_session_id
        header = struct.pack(">I", sid)    # same bytes as SensorLinkPacket.header()
        iv, ciphertext, tag = self._link_cipher.encrypt_detached(packet.to_bytes(), header)
        return SensorLinkPacket(sid, iv, ciphertext, tag)