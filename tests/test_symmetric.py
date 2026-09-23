from src.crypto.symmetric import AESGCMCipher


def test_encryption_decryption():
    cipher = AESGCMCipher.generate()
    print(f"the key is {cipher.key}")

    message = b"Heart rate: 78"
    print(f"the message is {message}")

    nonce, ciphertext = cipher.encrypt(message)
    print(f"the ciphertext is {ciphertext}")
    print(f"the nonce is {nonce}")

    decrypted = cipher.decrypt(
        nonce,
        ciphertext
    )
    print(f"the decrypted is {decrypted}")
    print(f"result of decrypted == message is : {decrypted == message}")

    assert decrypted == message