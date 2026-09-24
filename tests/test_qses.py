import pytest

from src.crypto.hashing import sha3_256
from src.crypto.kdf import derive_aes_key
from src.crypto.kem import KEMKeyPair
from src.crypto.signature import verify
from src.crypto.symmetric import AESGCMCipher
from src.entities.client import ClientNode
from src.entities.qses import QSESNode
from src.protocol.errors import ProtocolError
from src.protocol.messages import (
    EDGE_PACKET_SIZE, ClientPacket, EdgePacket, now_ms,
)


def setup(**qses_kwargs):
    print(" \n setting up")
    server = KEMKeyPair()
    client = ClientNode(client_id=1, server_id=9, session_id=3, qses_nonce=222)
    qses = QSESNode(server_public_key=server.public_key, **qses_kwargs)
    print("server,client and qses created successfully")
    qses.register_client(1, client.public_key)
    print("client registered successfully")
    return server, client, qses


def test_edge_packet_is_5832_bytes():
    print(" \n testing edge packet size")
    _, client, qses = setup()
    pkt = client.create_signed_reading(b"Heart rate: 78")
    print(f"client packet created successfully " )
    out = qses.process_and_forward(pkt)
    print(f"phase 2 packet created successfully ")
    out_bytes = out.to_bytes()
    print(f"\nphase 2 packet length: {len(out_bytes)} bytes")
    assert len(out_bytes) == EDGE_PACKET_SIZE == 5832


def test_qses_signature_verifies():
    print(" \n testing signature")
    _, client, qses = setup()
    out = qses.process_and_forward(client.create_signed_reading(b"x"))
    print(f"result of verify(sha3_256(out.signed_content()), out.signature, qses.public_key) === ", verify(sha3_256(out.signed_content()), out.signature, qses.public_key))
    assert verify(sha3_256(out.signed_content()), out.signature, qses.public_key)


def test_server_side_can_decrypt_back_to_client_packet():
    print(" \n testing decryption")
    server, client, qses = setup()
    pkt = client.create_signed_reading(b"Heart rate: 78")
    print(f"client packet's signed successfully ")
    out = qses.process_and_forward(pkt)
    print(f"out's signed successfully "  )
    ss = server.decapsulate(out.kem_ciphertext)
    print(f"decapsulation done successfully ")
    key = derive_aes_key(ss, out.salt)
    plain = AESGCMCipher(key).decrypt_detached(out.iv, out.ciphertext, out.tag)
    print(f"decryption done successfully")
    assert plain == pkt.to_bytes()

    assert ClientPacket.from_bytes(plain) == pkt
    # the wire bytes must not contain the plaintext telemetry
    assert b"Heart rate" not in out.to_bytes()


def test_wire_roundtrip():
    print(" \n testing wire roundtrip")
    _, client, qses = setup()
    out = qses.process_and_forward(client.create_signed_reading(b"x"))
   
    assert EdgePacket.from_bytes(out.to_bytes()) == out


def test_unknown_client_rejected():
    print(" \n testing unknown client")
    server = KEMKeyPair()
    print(f"server created kem key pair")
    client = ClientNode(client_id=1, server_id=9, session_id=3, qses_nonce=222)
    print(f"client created successfully")
    qses = QSESNode(server.public_key)          # client NOT registered
    print(f"qses created successfully but client is not registered")
    print(f"about to forward the packet to qses")

    with pytest.raises(ProtocolError, match="unknown client"):
        qses.process_and_forward(client.create_signed_reading(b"x"))


def test_replay_rejected():
    print(" \n testing replay")
    _, client, qses = setup()
    pkt = client.create_signed_reading(b"x")
    qses.process_and_forward(pkt)
    with pytest.raises(ProtocolError, match="sequence"):
        qses.process_and_forward(pkt)


def test_stale_timestamp_rejected():
    print(" \n testing stale timestamp")
    _, client, qses = setup(clock=lambda: now_ms() + 60_000)   # QSES clock 60 s ahead
    with pytest.raises(ProtocolError, match="stale"):
        qses.process_and_forward(client.create_signed_reading(b"x"))


def test_forged_telemetry_rejected_and_does_not_burn_seq():
    print(" \n testing forged telemetry")
    _, client, qses = setup()
    pkt = client.create_signed_reading(b"Heart rate: 78")
    print("created a valid client packet")
    forged = ClientPacket(b"Heart rate: 30".ljust(100, b"\x00"),pkt.meta, pkt.signature, pkt.hmac)
    print("created a forged client packet")
    with pytest.raises(ProtocolError, match="signature"):
        qses.process_and_forward(forged)
    # the genuine packet with the same seq is still accepted
    assert qses.process_and_forward(pkt) is not None