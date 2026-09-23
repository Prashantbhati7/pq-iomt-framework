import oqs

SIG_ALG = "ML-DSA-44"


class Signer:
    """Long-lived signing key pair (used by the device, QSES, and CA)."""

    def __init__(self):
        self._sig = oqs.Signature(SIG_ALG)
        self.public_key = self._sig.generate_keypair()

    def sign(self, message: bytes) -> bytes:
        return self._sig.sign(message)

    def close(self):
        self._sig.free()


def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    with oqs.Signature(SIG_ALG) as verifier:
        return verifier.verify(message, signature, public_key)