import pytest

from src.crypto.hashing import sha3_256
from src.entities.client import ClientNode
from src.entities.qses import QSESNode
from src.entities.server import MedicalServerNode
from src.protocol.errors import MaliciousEdgeError, ProtocolError
from src.protocol.messages import ClientPacket, EdgePacket, pad_telemetry


def setup(client_server_id=9, registered_qses_nonce=222,server_side_client_key=None, register=True):
    server = MedicalServerNode(server_id=9)
    client = ClientNode(client_id=1, server_id=client_server_id,session_id=3, qses_nonce=222)
    qses = QSESNode(server.public_key)
    qses.register_client(1, client.public_key)
    server.trust_qses(qses.public_key)
    if register:
        server.register_client(1, server_side_client_key or client.public_key, client.hmac_key, registered_qses_nonce)
    return server, client, qses


def send(client, qses, server, telemetry=b"Heart rate: 78"):
    return server.receive_and_verify(qses.process_and_forward(client.create_signed_reading(telemetry)))


def test_happy_path_stores_reading():
    server, client, qses = setup()
    stored = send(client, qses, server)
    print(f"\nstored: {stored.client_id=} {stored.seq=} {stored.message.rstrip(bytes(1))}")
    assert stored.message == pad_telemetry(b"Heart rate: 78")
    assert (stored.client_id, stored.seq) == (1, 1)
    assert server.database == [stored]


def test_accepts_raw_wire_bytes():
    server, client, qses = setup()
    out = qses.process_and_forward(client.create_signed_reading(b"x"))
    assert server.receive_and_verify(out.to_bytes()).seq == 1


def test_five_readings_in_order_no_anomalies():
    server, client, qses = setup()
    for i in range(5):
        send(client, qses, server, f"reading {i}".encode())
    assert len(server.database) == 5
    assert server.anomalies == [] and server.retransmit_requests == []


def test_tampered_ciphertext_rejected_by_transport_signature():
    server, client, qses = setup()
    out = qses.process_and_forward(client.create_signed_reading(b"x"))
    bad_c = bytes([out.ciphertext[0] ^ 1]) + out.ciphertext[1:]
    bad = EdgePacket(out.kem_ciphertext, out.salt, out.iv, bad_c, out.tag, out.signature)
    with pytest.raises(ProtocolError, match="transport signature"):
        server.receive_and_verify(bad)


def test_bad_tag_with_valid_qses_signature_rejected():
    # Simulates a compromised QSES that re-signs a packet with a corrupted tag.
    server, client, qses = setup()
    out = qses.process_and_forward(client.create_signed_reading(b"x"))
    bad_tag = bytes([out.tag[0] ^ 1]) + out.tag[1:]
    unsigned = EdgePacket(out.kem_ciphertext, out.salt, out.iv,
                          out.ciphertext, bad_tag, out.signature)
    resigned = qses._signer.sign(sha3_256(unsigned.signed_content()))
    bad = EdgePacket(out.kem_ciphertext, out.salt, out.iv,
                     out.ciphertext, bad_tag, resigned)
    with pytest.raises(ProtocolError, match="AES-GCM"):
        server.receive_and_verify(bad)


def test_misrouted_packet_rejected():
    server, client, qses = setup(client_server_id=8)     # packet addressed to server 8
    with pytest.raises(ProtocolError, match="misrouted"):
        send(client, qses, server)


def test_replay_of_same_edge_packet_rejected():
    server, client, qses = setup()
    out = qses.process_and_forward(client.create_signed_reading(b"x"))
    server.receive_and_verify(out)
    with pytest.raises(ProtocolError, match="replay"):
        server.receive_and_verify(out)
    assert len(server.database) == 1


def test_wrong_qses_nonce_rejected():
    server, client, qses = setup(registered_qses_nonce=999)
    with pytest.raises(ProtocolError, match="nonce"):
        send(client, qses, server)


def test_unknown_client_rejected_by_server():
    server, client, qses = setup(register=False)
    with pytest.raises(ProtocolError, match="unknown client"):
        send(client, qses, server)


def test_device_signature_checked_against_registered_key():
    other = ClientNode(client_id=1, server_id=9, session_id=3, qses_nonce=222)
    server, client, qses = setup(server_side_client_key=other.public_key)
    with pytest.raises(ProtocolError, match="device signature"):
        send(client, qses, server)


def test_sequence_gap_logged_and_retransmission_requested():
    server, client, qses = setup()
    p1 = client.create_signed_reading(b"a")
    _p2 = client.create_signed_reading(b"b")             # "lost" on the way
    p3 = client.create_signed_reading(b"c")
    server.receive_and_verify(qses.process_and_forward(p1))
    server.receive_and_verify(qses.process_and_forward(p3))
    print(f"\nanomalies: {server.anomalies}")
    assert len(server.database) == 2
    assert server.retransmit_requests == [(1, 2, 2)]
    assert server.anomalies


def test_bad_hmac_flags_malicious_qses_and_stores_nothing():
    server, client, qses = setup()
    pkt = client.create_signed_reading(b"x")
    tampered = ClientPacket(pkt.message, pkt.meta, pkt.signature, b"\x00" * 32)
    out = qses.process_and_forward(tampered)   # QSES can't see the hmac_key
    with pytest.raises(MaliciousEdgeError):
        server.receive_and_verify(out)
    assert server.qses_flagged
    assert server.database == []
    assert server.clients[1].last_seq == 0     # failed packet did not burn the seq