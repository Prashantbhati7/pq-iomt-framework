import pytest

from src.crypto.kem import KEMKeyPair
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
    cid, n_i, pk_kem, sig_d = client.begin_session()            # step 1: sensor -> QSES
    n_q, sid, ct, sig_q = qses.accept_session(cid, n_i, pk_kem, sig_d)   # step 2: QSES -> sensor
    client.complete_session(n_q, sid, ct, sig_q)                # step 3: sensor finishes
    return sid


def test_both_sides_derive_the_same_key():
    _, qses, client = make_system()
    sid = handshake(qses, client)
    assert client._link_cipher.key == qses.sessions[sid].key


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


def test_rogue_qses_reply_rejected_by_sensor():
    server, qses, client = make_system()
    rogue = SecureQSESNode(server.public_key)          # different signing key
    rogue.register_client(1, client.public_key)
    hello = client.begin_session()
    reply = rogue.accept_session(*hello)
    with pytest.raises(ProtocolError, match="reply"):
        client.complete_session(*reply)


def test_replayed_old_reply_rejected_by_sensor():
    _, qses, client = make_system()
    old_reply = qses.accept_session(*client.begin_session())   # attacker records this
    client.begin_session()                                     # new request: new n_i, new Kyber pair
    with pytest.raises(ProtocolError, match="reply"):
        client.complete_session(*old_reply)


def test_forged_hello_rejected_by_qses():
    _, qses, client = make_system()
    cid, n_i, pk_kem, sig_d = client.begin_session()
    with pytest.raises(ProtocolError, match="handshake signature"):
        qses.accept_session(cid, n_i, pk_kem, b"\x00" * len(sig_d))


def test_swapped_kyber_key_rejected_by_qses():
    _, qses, client = make_system()
    cid, n_i, pk_kem, sig_d = client.begin_session()
    attacker_pk = KEMKeyPair().public_key              # attacker substitutes their own padlock
    with pytest.raises(ProtocolError, match="handshake signature"):
        qses.accept_session(cid, n_i, attacker_pk, sig_d)


def test_replayed_hello_rejected_by_qses():
    _, qses, client = make_system()
    hello = client.begin_session()
    qses.accept_session(*hello)
    with pytest.raises(ProtocolError, match="replayed handshake"):
        qses.accept_session(*hello)