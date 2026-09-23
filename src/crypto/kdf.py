from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_aes_key(shared_secret: bytes, salt: bytes, info: bytes = b"AES-GCM") -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,             # 32 bytes = 256-bit AES key
        salt=salt,
        info=info,
    ).derive(shared_secret)