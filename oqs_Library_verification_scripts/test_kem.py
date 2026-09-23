import oqs

algorithm = "ML-KEM-512"

with oqs.KeyEncapsulation(algorithm) as gateway:
    public_key = gateway.generate_keypair()

    with oqs.KeyEncapsulation(algorithm) as device:
        ciphertext, device_secret = device.encap_secret(public_key)

    gateway_secret = gateway.decap_secret(ciphertext)

    print("Algorithm:", algorithm)
    print("Public key length:", len(public_key))
    print("Ciphertext length:", len(ciphertext))
    print("Shared secret length:", len(device_secret))
    print("Shared secrets match:", device_secret == gateway_secret)