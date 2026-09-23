import oqs
import hashlib

algorithm = "ML-KEM-512"

with oqs.KeyEncapsulation(algorithm) as gateway:
    public_key = gateway.generate_keypair()

    with oqs.KeyEncapsulation(algorithm) as device:
        ciphertext, device_secret = device.encap_secret(public_key)

    gateway_secret = gateway.decap_secret(ciphertext)

    # Device and gateway independently calculate confirmations
    device_confirmation = hashlib.sha256(
        b"key-confirmation" + device_secret
    ).digest()

    gateway_confirmation = hashlib.sha256(
        b"key-confirmation" + gateway_secret
    ).digest()

    print("Original keys match:",
          device_secret == gateway_secret)

    print("Confirmation matches:",
          device_confirmation == gateway_confirmation)

    # Tamper with ciphertext
    modified_ciphertext = bytearray(ciphertext)
    modified_ciphertext[0] ^= 1

    modified_secret = gateway.decap_secret(
        bytes(modified_ciphertext)
    )

    modified_confirmation = hashlib.sha256(
        b"key-confirmation" + modified_secret
    ).digest()

    print("Modified confirmation matches:",
          device_confirmation == modified_confirmation)