import pytest

from src.entities.secure_client import SecureClientNode
from src.entities.secure_qses import SecureQSESNode
from src.entities.server import MedicalServerNode
from src.protocol.errors import ProtocolError
from src.protocol.messages import pad_telemetry
from src.protocol.secure_messages import LINK_PACKET_SIZE, SensorLinkPacket


def make_system():
    server = MedicalServerNode(server_id=9)
    qses = SecureQSESNode(server.public_key)
    client = SecureClientNode(client_id=1, server_id=9, session_id=3, qses_nonce=222,
                              qses_public_key=qses.public_key)
    qses.register_client(1, client.public_key)
    server.trust_qses(qses.public_key)
    server.register_client(1, client.public_key, client.hmac_key, 222)
    return server, qses, client


def handshake(qses, client):
    cid, n_i = client.begin_session()
    pk_kem, n_q, sid, sig_q = qses.offer_session(cid, n_i)
    ct, sig_d = client.complete_session(pk_kem, n_q, sid, sig_q)
    return qses.finish_session(cid, ct, sig_d)


def test_end_to_end_reading_is_stored():
    server, qses, client = make_system()
    handshake(qses, client)
    pkt = client.create_encrypted_reading(b"Heart rate: 78")
    stored = server.receive_and_verify(qses.receive_from_sensor(pkt))
    assert stored.message == pad_telemetry(b"Heart rate: 78")


def test_eavesdropper_cannot_read_sensor_link():
    _, qses, client = make_system()
    handshake(qses, client)
    captured = client.create_encrypted_reading(b"Heart rate: 78").to_bytes()
    print(f"\nlink packet: {len(captured)} bytes, starts with {captured[:16].hex()}")
    assert len(captured) == LINK_PACKET_SIZE == 2616
    assert b"Heart rate" not in captured


def test_wire_roundtrip():
    _, qses, client = make_system()
    handshake(qses, client)
    pkt = client.create_encrypted_reading(b"x")
    assert SensorLinkPacket.from_bytes(pkt.to_bytes()) == pkt


def test_no_session_no_send():
    _, _, client = make_system()
    with pytest.raises(ProtocolError, match="no session"):
        client.create_encrypted_reading(b"x")


def test_tampered_ciphertext_rejected_by_gcm():
    _, qses, client = make_system()
    handshake(qses, client)
    pkt = client.create_encrypted_reading(b"x")
    bad_c = bytes([pkt.ciphertext[0] ^ 1]) + pkt.ciphertext[1:]
    bad = SensorLinkPacket(pkt.session_id, pkt.iv, bad_c, pkt.tag)
    with pytest.raises(ProtocolError, match="AES-GCM"):
        qses.receive_from_sensor(bad)


def test_tampered_session_id_rejected():
    _, qses, client = make_system()
    handshake(qses, client)
    pkt = client.create_encrypted_reading(b"x")
    bad = SensorLinkPacket(pkt.session_id ^ 1, pkt.iv, pkt.ciphertext, pkt.tag)
    with pytest.raises(ProtocolError, match="unknown session"):
        qses.receive_from_sensor(bad)


def test_replayed_link_packet_rejected():
    _, qses, client = make_system()
    handshake(qses, client)
    pkt = client.create_encrypted_reading(b"x")
    qses.receive_from_sensor(pkt)
    with pytest.raises(ProtocolError, match="sequence"):
        qses.receive_from_sensor(pkt)


def test_rogue_qses_offer_rejected_by_sensor():
    server, qses, client = make_system()
    rogue = SecureQSESNode(server.public_key)          # different signing key
    rogue.register_client(1, client.public_key)
    cid, n_i = client.begin_session()
    pk_kem, n_q, sid, sig_q = rogue.offer_session(cid, n_i)
    with pytest.raises(ProtocolError, match="offer"):
        client.complete_session(pk_kem, n_q, sid, sig_q)


def test_replayed_old_offer_rejected_by_sensor():
    _, qses, client = make_system()
    cid, n_i = client.begin_session()
    old_offer = qses.offer_session(cid, n_i)           # attacker records this
    cid, n_i2 = client.begin_session()                 # a new session, new n_i
    with pytest.raises(ProtocolError, match="offer"):
        client.complete_session(*old_offer)


def test_forged_finish_rejected_by_qses():
    _, qses, client = make_system()
    cid, n_i = client.begin_session()
    pk_kem, n_q, sid, sig_q = qses.offer_session(cid, n_i)
    ct, sig_d = client.complete_session(pk_kem, n_q, sid, sig_q)
    with pytest.raises(ProtocolError, match="handshake signature"):
        qses.finish_session(cid, ct, b"\x00" * len(sig_d))