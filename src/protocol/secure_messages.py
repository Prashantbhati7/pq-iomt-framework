"""Wire format and signed handshake bytes for the sensor <-> QSES session link.

New file: the baseline messages.py is left untouched so the paper's version
stays available for before/after comparison.
"""
import struct
from dataclasses import dataclass

from src.protocol.messages import CLIENT_PACKET_SIZE, IV_SIZE, TAG_SIZE, _check_len, _split

SESSION_ID_SIZE = 4
NONCE_SIZE = 16
LINK_PACKET_SIZE = SESSION_ID_SIZE + IV_SIZE + CLIENT_PACKET_SIZE + TAG_SIZE   # 2616
SESSION_INFO = b"sensor-qses-session"      # HKDF label: ties the key to this link


def _u32(x: int) -> bytes:
    return struct.pack(">I", x)


def hello_bytes(client_id: int, n_i: bytes, pk_kem: bytes) -> bytes:
    """What the sensor signs in handshake step 1 (sigma_D): its id, nonce and Kyber public key."""
    return b"HELLO" + _u32(client_id) + n_i + pk_kem


def reply_bytes(client_id: int, n_i: bytes, n_q: bytes, session_id: int, ct: bytes) -> bytes:
    """What the QSES signs in handshake step 2 (sigma_Q). Contains the sensor's n_i."""
    return b"REPLY" + _u32(client_id) + n_i + n_q + _u32(session_id) + ct


@dataclass(frozen=True)
class SensorLinkPacket:
    """Sensor -> QSES, after the handshake. `ciphertext` is the encrypted ClientPacket."""
    session_id: int
    iv: bytes
    ciphertext: bytes
    tag: bytes

    def __post_init__(self):
        _check_len("iv", self.iv, IV_SIZE)
        _check_len("ciphertext", self.ciphertext, CLIENT_PACKET_SIZE)
        _check_len("tag", self.tag, TAG_SIZE)

    def header(self) -> bytes:
        """Sent in the clear, but authenticated by GCM (used as associated data)."""
        return _u32(self.session_id)

    def to_bytes(self) -> bytes:
        return self.header() + self.iv + self.ciphertext + self.tag

    @classmethod
    def from_bytes(cls, data: bytes) -> "SensorLinkPacket":
        _check_len("link packet", data, LINK_PACKET_SIZE)
        sid, iv, c, tag = _split(data, [SESSION_ID_SIZE, IV_SIZE, CLIENT_PACKET_SIZE, TAG_SIZE])
        return cls(struct.unpack(">I", sid)[0], iv, c, tag)