import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AESGCMCipher:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("AES-256 requires a 32-byte key")
        self.key = key

    @classmethod
    def generate(cls):
        return cls(AESGCM.generate_key(bit_length=256))

    def encrypt(self, plaintext: bytes, associated_data: bytes = None):
        nonce = os.urandom(12)

        aesgcm = AESGCM(self.key)

        ciphertext = aesgcm.encrypt(
            nonce,
            plaintext,
            associated_data
        )

        return nonce, ciphertext

    def decrypt(
        self,
        nonce: bytes,
        ciphertext: bytes,
        associated_data: bytes = None
    ):
        aesgcm = AESGCM(self.key)

        return aesgcm.decrypt(
            nonce,
            ciphertext,
            associated_data
        )
    def encrypt_detached(self, plaintext: bytes, associated_data: bytes = None):
        nonce, blob = self.encrypt(plaintext, associated_data)
        return nonce, blob[:-16], blob[-16:]

    def decrypt_detached(self, nonce: bytes, ciphertext: bytes, tag: bytes,associated_data: bytes = None):
        return self.decrypt(nonce, ciphertext + tag, associated_data)
    

