from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac


def sha3_256(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA3_256())
    h.update(data)
    return h.finalize()


def hmac_sha3_256(key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA3_256())
    h.update(data)
    return h.finalize()


def hmac_verify(key: bytes, data: bytes, tag: bytes) -> bool:
    h = hmac.HMAC(key, hashes.SHA3_256())
    h.update(data)
    try:
        h.verify(tag)          # constant-time comparison
        return True
    except InvalidSignature:
        return False