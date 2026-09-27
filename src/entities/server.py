"""Medical Server: verifies QSES, decapsulates, decrypts, verifies the device, stores telemetry."""
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag

from src.crypto.hashing import sha3_256, hmac_verify
from src.crypto.kdf import derive_aes_key
from src.crypto.kem import KEMKeyPair
from src.crypto.signature import verify
from src.crypto.symmetric import AESGCMCipher
from src.protocol.errors import MaliciousEdgeError, ProtocolError
from src.protocol.messages import ClientPacket, EdgePacket


@dataclass(frozen=True)
class StoredReading:
    client_id: int
    seq: int
    timestamp_ms: int
    message: bytes            # the 100-byte telemetry M (zero-padded)


@dataclass
class ClientRecord:
    public_key: bytes         # pk_Di
    hmac_key: bytes           # shared at registration (documented deviation)
    qses_nonce: int           # n_q issued to this device
    last_seq: int = 0
    seen_nonces: set = field(default_factory=set)


class MedicalServerNode:
    def __init__(self, server_id: int):
        self.server_id = server_id
        self._kem = KEMKeyPair()                 # (pk_Server, sk_Server)
        self.qses_public_key = None              # pk_QSES
        self.clients = {}                        # client_id -> ClientRecord
        self.database = []                       # accepted StoredReading objects
        self.anomalies = []                      # human-readable log lines
        self.retransmit_requests = []            # (client_id, first_missing, last_missing)
        self.qses_flagged = False

    @property
    def public_key(self) -> bytes:
        return self._kem.public_key

    def trust_qses(self, qses_public_key: bytes):
        self.qses_public_key = qses_public_key

    def register_client(self, client_id: int, public_key: bytes, hmac_key: bytes, qses_nonce: int):
        self.clients[client_id] = ClientRecord(public_key, hmac_key, qses_nonce)

    def receive_and_verify(self, packet) -> StoredReading:
        """Algorithm 3. Accepts an EdgePacket (or its raw 5832 bytes)."""
        if isinstance(packet, (bytes, bytearray)):
            packet = EdgePacket.from_bytes(bytes(packet))

        # --- 1. QSES transport signature ---
        if self.qses_public_key is None:
            raise ProtocolError("no trusted QSES key configured")
        if not verify(sha3_256(packet.signed_content()), packet.signature, self.qses_public_key):
            raise ProtocolError("invalid QSES transport signature")

        # --- 2. decapsulate, derive key, decrypt ---
        shared_secret = self._kem.decapsulate(packet.kem_ciphertext)
        key = derive_aes_key(shared_secret, packet.salt)
        try:
            plaintext = AESGCMCipher(key).decrypt_detached(packet.iv, packet.ciphertext, packet.tag)
        except InvalidTag:
            raise ProtocolError("AES-GCM authentication failed") from None

        inner = ClientPacket.from_bytes(plaintext)
        meta = inner.metadata

        # --- 3. metadata, sequence and nonce checks (read-only for now) ---
        if meta.server_id != self.server_id:
            raise ProtocolError("misrouted packet: wrong server_id")

        record = self.clients.get(meta.client_id)
        if record is None:
            raise ProtocolError(f"unknown client {meta.client_id}")

        if meta.qses_nonce != record.qses_nonce:
            raise ProtocolError("QSES nonce mismatch")
        if meta.client_nonce in record.seen_nonces:
            raise ProtocolError("replayed client nonce")
        if meta.seq <= record.last_seq:
            raise ProtocolError("replayed or out-of-order sequence number")

        expected = record.last_seq + 1
        gap = meta.seq > expected

        # --- 4. device end-to-end signature ---
        if not verify(sha3_256(inner.signed_content()), inner.signature,
                      record.public_key):
            raise ProtocolError("invalid device signature")

        # --- 5. HMAC ---
        if not hmac_verify(record.hmac_key, inner.signed_content(), inner.hmac):
            self.qses_flagged = True
            self.anomalies.append(f"client {meta.client_id} seq {meta.seq}: "
                                  "HMAC mismatch, QSES flagged as malicious")
            raise MaliciousEdgeError("HMAC mismatch after valid device signature")

        # --- 6. everything passed: commit state and store ---
        if gap:
            self.anomalies.append(
                f"client {meta.client_id}: expected seq {expected}, got {meta.seq}")
            self.retransmit_requests.append((meta.client_id, expected, meta.seq - 1))
        record.last_seq = meta.seq
        record.seen_nonces.add(meta.client_nonce)

        reading = StoredReading(meta.client_id, meta.seq, meta.timestamp_ms, inner.message)
        self.database.append(reading)
        return reading

    def close(self):
        self._kem.close()