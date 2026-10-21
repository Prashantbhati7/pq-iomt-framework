"""IoMT device with a per-session AES key shared with the QSES.

Kyber (ML-KEM-512) runs once per session. The SENSOR makes a fresh Kyber pair,
the QSES runs Encaps against the sensor's public key, and the sensor runs
Decaps. Every reading after that is signed exactly as in the paper
(Algorithm 1) and then encrypted with AES-256-GCM.
"""
import os
import struct

from src.crypto.hashing import sha3_256
from src.crypto.kdf import derive_aes_key
from src.crypto.kem import KEMKeyPair
from src.crypto.signature import verify
from src.crypto.symmetric import AESGCMCipher
from src.entities.client import ClientNode
from src.protocol.errors import ProtocolError
from src.protocol.secure_messages import (
    NONCE_SIZE, SESSION_INFO, SensorLinkPacket, hello_bytes, reply_bytes,
)


class SecureClientNode(ClientNode):
    def __init__(self, *args, qses_public_key: bytes, **kwargs):
        super().__init__(*args, **kwargs)
        self._qses_public_key = qses_public_key   # pk_QSES (signing key), loaded at enrollment
        self._n_i = None
        self._kem = None                          # fresh Kyber pair for the handshake in progress
        self._link_cipher = None                  # AES-GCM with the session key K
        self._link_session_id = None

    # ---- handshake (once per session) ----------------------------------

    def begin_session(self):
        """Step 1: make a fresh Kyber pair, sign the public half.

        Returns (id, n_i, pk_kem, sigma_D), the message sent to the QSES.
        """
        if self._kem is not None:
            self._kem.close()                     # drop an unfinished earlier attempt
        self._n_i = os.urandom(NONCE_SIZE)
        self._kem = KEMKeyPair()                  # (pk_kem, sk_kem), used for this session only
        pk_kem = self._kem.public_key
        sig_d = self._signer.sign(sha3_256(hello_bytes(self.client_id, self._n_i, pk_kem)))
        return self.client_id, self._n_i, pk_kem, sig_d

    def complete_session(self, n_q: bytes, session_id: int, ct: bytes, sig_q: bytes):
        """Step 3: check the QSES reply, run Decaps, derive K, delete the Kyber private key."""
        if self._kem is None:
            raise ProtocolError("no handshake in progress")
        reply = reply_bytes(self.client_id, self._n_i, n_q, session_id, ct)
        if not verify(sha3_256(reply), sig_q, self._qses_public_key):
            raise ProtocolError("invalid QSES reply signature")

        ss = self._kem.decapsulate(ct)
        key = derive_aes_key(ss, self._n_i + n_q, info=SESSION_INFO)
        self._link_cipher = AESGCMCipher(key)
        self._link_session_id = session_id

        self._kem.close()                         # sk_kem is gone: forward secrecy for this link
        self._kem = None
        self._n_i = None

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