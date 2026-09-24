from src.crypto.hashing import sha3_256, hmac_verify
from src.crypto.signature import verify
from src.entities.client import ClientNode
from src.protocol.messages import CLIENT_PACKET_SIZE, ClientPacket


def make_client():
    return ClientNode(client_id=1, server_id=9, session_id=3, qses_nonce=222)


def test_packet_is_2584_bytes():
    print("\n \n testing packet size")
    client = make_client()
    pkt = client.create_signed_reading(b"Heart rate: 78")
    print(f"\npacket size: {len(pkt.to_bytes())}")
    assert len(pkt.to_bytes()) == CLIENT_PACKET_SIZE == 2584
    assert ClientPacket.from_bytes(pkt.to_bytes()) == pkt           # checking if to_bytes is reversible


def test_signature_and_hmac_verify():
    print("\n \n testing signature and hmac")
    client = make_client()
    pkt = client.create_signed_reading(b"Heart rate: 78")
    content = pkt.signed_content()                       # M || meta
    print(f"the signed content is: {content}")
    res = "Valid" if verify(sha3_256(content), pkt.signature, client.public_key) else "Invalid"
    print(f"verification result is {res}")
    assert verify(sha3_256(content), pkt.signature, client.public_key)
    assert hmac_verify(client.hmac_key, content, pkt.hmac)


def test_metadata_fields():
    print("\n \n testing metadata fields")
    client = make_client()
    m = client.create_signed_reading(b"x").metadata
    print(f"\nmetadata: {m}")
    assert (m.client_id, m.seq, m.session_id, m.server_id, m.qses_nonce) == (1, 1, 3, 9, 222)


def test_sequence_increments_and_nonces_differ():
    print("\n \n testing sequence increments and nonces")
    client = make_client()
    a = client.create_signed_reading(b"a").metadata
    b = client.create_signed_reading(b"b").metadata
    print(f"\nmetadata a: {a}")
    print(f"metadata b: {b}")
    assert (a.seq, b.seq) == (1, 2)
    assert a.client_nonce != b.client_nonce


def test_tampered_telemetry_fails_verification():
    print("\n \n testing tampered telemetry")
    client = make_client()
    pkt = client.create_signed_reading(b"Heart rate: 78") 
    forged = b"Heart rate: 30".ljust(100, b"\x00") + pkt.meta  # tampering only the message 
    res = "Valid" if verify(sha3_256(forged), pkt.signature, client.public_key) else "Invalid"
    print(f"verification result is {res}")
    assert not verify(sha3_256(forged), pkt.signature, client.public_key)
    assert not hmac_verify(client.hmac_key, forged, pkt.hmac)