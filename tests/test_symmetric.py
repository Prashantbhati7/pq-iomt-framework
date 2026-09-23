from src.crypto.symmetric import AESGCMCipher


def test_encryption_decryption():
    cipher = AESGCMCipher.generate()

    message = b"Heart rate: 78"

    nonce, ciphertext = cipher.encrypt(message)

    decrypted = cipher.decrypt(
        nonce,
        ciphertext
    )

    assert decrypted == message