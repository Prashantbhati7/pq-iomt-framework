"""Wire formats for the PQ-IoMT protocol. No cryptography here, only layout."""
import struct
import time
from dataclasses import dataclass

# ---- Fixed field sizes in bytes (from the paper / verified by tests) ----
TELEMETRY_SIZE = 100
META_SIZE = 32
HMAC_SIZE = 32
SIG_SIZE = 2420          # ML-DSA-44 signature
KEM_CT_SIZE = 768        # ML-KEM-512 ciphertext
SALT_SIZE = 32
IV_SIZE = 12
TAG_SIZE = 16

CLIENT_PACKET_SIZE = TELEMETRY_SIZE + META_SIZE + SIG_SIZE + HMAC_SIZE          # 2584
EDGE_PACKET_SIZE = (KEM_CT_SIZE + SALT_SIZE + IV_SIZE + CLIENT_PACKET_SIZE + TAG_SIZE + SIG_SIZE)                  # 5832

# ">IIQIIII" = big-endian: 4+4+8+4+4+4+4 = 32 bytes
_META_FORMAT = ">IIQIIII"
assert struct.calcsize(_META_FORMAT) == META_SIZE


def now_ms() -> int:
    return int(time.time() * 1000)


def pad_telemetry(data: bytes) -> bytes:
    """Zero-pad a reading (e.g. b'Heart rate: 78') to the paper's 100 bytes."""
    if len(data) > TELEMETRY_SIZE:
        raise ValueError(f"telemetry longer than {TELEMETRY_SIZE} bytes")
    return data.ljust(TELEMETRY_SIZE, b"\x00")

def _check_len(name: str, data: bytes, expected: int):
    if len(data) != expected:
        raise ValueError(f"{name} must be {expected} bytes, got {len(data)}")


def _split(data: bytes, sizes):
    parts, offset = [], 0
    for size in sizes:
        parts.append(data[offset:offset + size])
        offset += size
    return parts


@dataclass(frozen=True)
class Metadata:
    client_id: int
    seq: int
    timestamp_ms: int
    client_nonce: int
    qses_nonce: int
    session_id: int
    server_id: int

    def to_bytes(self) -> bytes:
        return struct.pack(_META_FORMAT, self.client_id, self.seq, self.timestamp_ms, self.client_nonce, self.qses_nonce, self.session_id, self.server_id)

    @classmethod
    def from_bytes(cls, data: bytes) -> "Metadata":
        _check_len("meta", data, META_SIZE)
        return cls(*struct.unpack(_META_FORMAT, data))


@dataclass(frozen=True)
class ClientPacket:
    """Packet 1: device -> QSES. Also the plaintext payload P that QSES encrypts."""
    message: bytes
    meta: bytes        # kept as raw bytes so we verify exactly what was signed
    signature: bytes
    hmac: bytes

    def __post_init__(self):
        _check_len("message", self.message, TELEMETRY_SIZE)
        _check_len("meta", self.meta, META_SIZE)
        _check_len("signature", self.signature, SIG_SIZE)
        _check_len("hmac", self.hmac, HMAC_SIZE)

    @property
    def metadata(self) -> Metadata:
        return Metadata.from_bytes(self.meta)

    def signed_content(self) -> bytes:
        """M || meta: what gets hashed and signed (and what the HMAC covers)."""
        return self.message + self.meta

    def to_bytes(self) -> bytes:
        return self.message + self.meta + self.signature + self.hmac

    @classmethod
    def from_bytes(cls, data: bytes) -> "ClientPacket":
        _check_len("client packet", data, CLIENT_PACKET_SIZE)
        return cls(*_split(data, [TELEMETRY_SIZE, META_SIZE, SIG_SIZE, HMAC_SIZE]))


@dataclass(frozen=True)
class EdgePacket:
    """Packet 2: QSES -> Medical Server."""
    kem_ciphertext: bytes
    salt: bytes
    iv: bytes
    ciphertext: bytes   # C, the encrypted ClientPacket
    tag: bytes
    signature: bytes    # QSES signature over signed_content()

    def __post_init__(self):
        _check_len("kem_ciphertext", self.kem_ciphertext, KEM_CT_SIZE)
        _check_len("salt", self.salt, SALT_SIZE)
        _check_len("iv", self.iv, IV_SIZE)
        _check_len("ciphertext", self.ciphertext, CLIENT_PACKET_SIZE)
        _check_len("tag", self.tag, TAG_SIZE)
        _check_len("signature", self.signature, SIG_SIZE)

    def signed_content(self) -> bytes:
        """D = ct || salt || IV || C || tag (everything except the signature)."""
        return self.kem_ciphertext + self.salt + self.iv + self.ciphertext + self.tag

    def to_bytes(self) -> bytes:
        return self.signed_content() + self.signature

    @classmethod
    def from_bytes(cls, data: bytes) -> "EdgePacket":
        _check_len("edge packet", data, EDGE_PACKET_SIZE)
        return cls(*_split(data, [KEM_CT_SIZE, SALT_SIZE, IV_SIZE, CLIENT_PACKET_SIZE, TAG_SIZE, SIG_SIZE]))