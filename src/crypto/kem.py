import oqs

KEM_ALG = "ML-KEM-512"


class KEMKeyPair:
    """Long-lived key pair (used by the Medical Server)."""

    def __init__(self):
        self._kem = oqs.KeyEncapsulation(KEM_ALG)
        self.public_key = self._kem.generate_keypair()

    def decapsulate(self, ciphertext: bytes) -> bytes:
        return self._kem.decap_secret(ciphertext)

    def close(self):
        self._kem.free()


def encapsulate(public_key: bytes):
    """Used by QSES. Returns (ciphertext, shared_secret)."""
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        return kem.encap_secret(public_key)