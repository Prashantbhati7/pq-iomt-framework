"""QSES edge server: verifies the device, then encapsulates, encrypts and signs."""
import os

from src.crypto.hashing import sha3_256
from src.crypto.kdf import derive_aes_key
from src.crypto.kem import encapsulate
from src.crypto.signature import Signer, verify
from src.crypto.symmetric import AESGCMCipher
from src.protocol.errors import ProtocolError
from src.protocol.messages import ClientPacket, EdgePacket, SALT_SIZE, now_ms


class QSESNode:
    def __init__(self, server_public_key: bytes, max_age_ms: int = 5000, clock=now_ms):
        self._signer = Signer()                    # (pk_QSES, sk_QSES)
        self.server_public_key = server_public_key # pk_Server (ML-KEM-512)
        self.max_age_ms = max_age_ms               # freshness window
        self._clock = clock                        # injectable so tests can fake time
        self.client_registry = {}                  # client_id -> pk_Di  (the paper's CR)
        self.last_seq = {}                         # client_id -> last accepted seq

    @property
    def public_key(self) -> bytes:
        return self._signer.public_key

    def register_client(self, client_id: int, public_key: bytes):
        self.client_registry[client_id] = public_key

    def process_and_forward(self, packet) -> EdgePacket:
        """Algorithm 2. Accepts a ClientPacket (or its raw 2584 bytes)."""
        if isinstance(packet, (bytes, bytearray)):
            packet = ClientPacket.from_bytes(bytes(packet))

        meta = packet.metadata

        # --- 1. verification and freshness -----------
        pk_client = self.client_registry.get(meta.client_id)
        if pk_client is None:
            raise ProtocolError(f"unknown client {meta.client_id}")

        if abs(self._clock() - meta.timestamp_ms) > self.max_age_ms:
            raise ProtocolError("stale timestamp")

        if meta.seq <= self.last_seq.get(meta.client_id, 0):
            raise ProtocolError("replayed or out-of-order sequence number")

        if not verify(sha3_256(packet.signed_content()), packet.signature, pk_client):
            raise ProtocolError("invalid device signature")

        self.last_seq[meta.client_id] = meta.seq   # update only after verification

        # --- 2. ML-KEM encapsulation ---
        kem_ct, shared_secret = encapsulate(self.server_public_key)

        # --- 3. HKDF -> AES-256 key ---
        salt = os.urandom(SALT_SIZE)
        key = derive_aes_key(shared_secret, salt)

        # --- 4. AES-256-GCM over the whole client packet ---
        iv, ciphertext, tag = AESGCMCipher(key).encrypt_detached(packet.to_bytes())

        # --- 5. QSES transport signature over D = ct || salt || IV || C || tag ---
        unsigned = EdgePacket(kem_ct, salt, iv, ciphertext, tag, b"\x00" * 2420)
        signature = self._signer.sign(sha3_256(unsigned.signed_content()))

        return EdgePacket(kem_ct, salt, iv, ciphertext, tag, signature)

    def close(self):
        self._signer.close()