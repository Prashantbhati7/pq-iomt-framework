import oqs

algorithm = "ML-DSA-44"
message = b"Hello Post Quantum Cryptography"

with oqs.Signature(algorithm) as signer:
    public_key = signer.generate_keypair()

    signature = signer.sign(message)

    is_valid = signer.verify(
        message,
        signature,
        public_key
    )

    print("Algorithm:", algorithm)
    print("Signature valid:", is_valid)
