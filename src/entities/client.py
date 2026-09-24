"""IoMT device. Signs telemetry only; never encrypts (QSES does that)."""
import os

from src.crypto.hashing import sha3_256, hmac_sha3_256
from src.crypto.signature import Signer
from src.protocol.messages import ClientPacket, Metadata, now_ms, pad_telemetry


class ClientNode:
    def __init__(self, client_id: int, server_id: int, session_id: int,qses_nonce: int, hmac_key: bytes = None):
        self.client_id = client_id
        self.server_id = server_id
        self.session_id = session_id
        self.qses_nonce = qses_nonce            
        self.seq = 0
        self._signer = Signer()                
        self.hmac_key = hmac_key or os.urandom(32)

    @property
    def public_key(self) -> bytes:
        return self._signer.public_key

    def create_signed_reading(self, telemetry: bytes) -> ClientPacket:
        """Algorithm 1: build (Message, meta, sigma, hmac)."""
        message = pad_telemetry(telemetry)
        self.seq += 1
        meta = Metadata(client_id=self.client_id, seq=self.seq, timestamp_ms=now_ms(), client_nonce=int.from_bytes(os.urandom(4), "big"),qses_nonce=self.qses_nonce, session_id=self.session_id,server_id=self.server_id).to_bytes()

        content = message + meta               
        signature = self._signer.sign(sha3_256(content))
        mac = hmac_sha3_256(self.hmac_key, content)

        return ClientPacket(message, meta, signature, mac)
    def close(self):
        self._signer.close()