import pytest
from cryptography.exceptions import InvalidTag

from src.crypto.hashing import sha3_256, hmac_sha3_256, hmac_verify
from src.crypto.kdf import derive_aes_key
from src.crypto.kem import KEMKeyPair, encapsulate
from src.crypto.signature import Signer, verify
from src.crypto.symmetric import AESGCMCipher


def test_sizes_match_paper():
    print("\n \n testing sizes")
    server = KEMKeyPair()
    # print(f"the server public key is: {server.public_key}")
    ct, ss = encapsulate(server.public_key)
    # print(f"the ciphertext is: {ct}")
    print(f"the shared secret is: {ss}")
    print(f"Length of server public key is: {len(server.public_key)}")    # 800
    print(f"Length of ciphertext is: {len(ct)}")              # 768
    print(f"Length of shared secret is: {len(ss)}")            # 32
    assert len(ct) == 768          # paper: 768 B KEM ciphertext
    assert len(ss) == 32

    signer = Signer()
    sig = signer.sign(sha3_256(b"hello"))
    # print(f"the signature is: {sig}")
    print(f"Length of signature is: {len(sig)}")      # 2420

    assert len(sig) == 2420        # paper: 2,420 B signature
    assert len(sha3_256(b"x")) == 32
    assert len(hmac_sha3_256(b"k" * 32, b"x")) == 32


def test_signature_valid_and_tamper_detected():
    print("\n \n testing signature")
    signer = Signer()
    h = sha3_256(b"telemetry")     # hashed 
    print(f"the hash is: {h}")
    sig = signer.sign(h)    # signed 
    # print(f"the signature is: {sig}")
    print(f"Length of signature is: {len(sig)}")   #. 2420
    assert verify(h, sig, signer.public_key)

    assert not verify(sha3_256(b"other"), sig, signer.public_key)


def test_hmac():
    print("\n \n testing HMAC")
    key, data = b"k" * 32, b"data"
    tag = hmac_sha3_256(key, data)
    print(f"the tag is: {tag}")
    print(f"Length of tag is: {len(tag)}")   # 32

    assert hmac_verify(key, data, tag)
    assert not hmac_verify(key, b"tampered", tag)


def test_kem_hkdf_aes_roundtrip():
    print("\n \n testing KEM HKDF AES roundtrip")
    server = KEMKeyPair()
    ct, ss_edge = encapsulate(server.public_key)         # QSES side
    # print(f"the ciphertext is: {ct}")
    print(f"the shared secret is: {ss_edge}")   
    print(f"length of shared secret is: {len(ss_edge)}")
    salt = b"\x01" * 32
    key_edge = derive_aes_key(ss_edge, salt)
    print(f"the key edge is: {key_edge}")
    print(f"Length of key edge is: {len(key_edge)}")   # 32

    iv, c, tag = AESGCMCipher(key_edge).encrypt_detached(b"Heart rate: 78")
    print(f"the iv is: {iv}")
    print(f"the ciphertext is: {c}")
    print(f"the tag is: {tag}") 
    print(f"Length of iv is: {len(iv)}")   # 12
    print(f"Length of ciphertext is: {len(c)}")  # 14
    print(f"Length of tag is: {len(tag)}")   # 16

    ss_srv = server.decapsulate(ct)                      # server side
    key_srv = derive_aes_key(ss_srv, salt)
    print(f"the key srv is: {key_srv}")     
    print(f"Length of key srv is: {len(key_srv)}")     # 32
    assert AESGCMCipher(key_srv).decrypt_detached(iv, c, tag) == b"Heart rate: 78"


def test_tampered_ciphertext_rejected():
    print("\n \n testing tampering")
    key = AESGCMCipher.generate().key
    print(f"the key is: {key}")
    print(f"Length of key is: {len(key)}")    # 32
    
    cipher = AESGCMCipher(key)
    iv, c, tag = cipher.encrypt_detached(b"secret")
    print(f"the iv is: {iv}")
    print(f"the ciphertext is: {c}")
    print(f"the tag is: {tag}")
    print(f"Length of iv is: {len(iv)}")      # 12
    print(f"Length of ciphertext is: {len(c)}")    # 6
    print(f"Length of tag is: {len(tag)}")     # 16
    
    bad = bytes([c[0] ^ 1]) + c[1:]
    print(f"the bad ciphertext is: {bad}")
    print(f"Length of bad ciphertext is: {len(bad)}")     # 6
    
    with pytest.raises(InvalidTag):
        cipher.decrypt_detached(iv, bad, tag)