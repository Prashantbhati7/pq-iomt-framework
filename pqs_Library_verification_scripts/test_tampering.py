import oqs

algorithm = "ML-KEM-512"

with oqs.KeyEncapsulation(algorithm) as gateway:

    # Gateway generates key pair
    public_key = gateway.generate_keypair()

    # Device encapsulates
    with oqs.KeyEncapsulation(algorithm) as device:
        ciphertext, device_secret = device.encap_secret(public_key)

    # Gateway decapsulates original ciphertext
    original_secret = gateway.decap_secret(ciphertext)

    # Attacker modifies one byte of ciphertext
    modified_ciphertext = bytearray(ciphertext)
    modified_ciphertext[0] ^= 1
    modified_ciphertext = bytes(modified_ciphertext)

    # Gateway decapsulates modified ciphertext
    modified_secret = gateway.decap_secret(modified_ciphertext)

    print("Original secrets match:",
          device_secret == original_secret)

    print("Modified secret matches original:",
          device_secret == modified_secret)

    print("Original secret:",
          original_secret.hex())

    print("Modified secret:",
          modified_secret.hex())
