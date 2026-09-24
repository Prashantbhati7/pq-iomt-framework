import pytest

from src.crypto.signature import Signer
from src.protocol.messages import (
    CLIENT_PACKET_SIZE, EDGE_PACKET_SIZE, SIG_SIZE, TELEMETRY_SIZE,
    ClientPacket, EdgePacket, Metadata, now_ms, pad_telemetry,
)


def make_meta():
    return Metadata(client_id=1, seq=7, timestamp_ms=now_ms(),
                    client_nonce=111, qses_nonce=222,
                    session_id=3, server_id=9)


def test_metadata_is_32_bytes_and_roundtrips():
    meta = make_meta()
    raw = meta.to_bytes()
    print(f"\nmeta length: {len(raw)}")
    assert len(raw) == 32
    assert Metadata.from_bytes(raw) == meta


def test_sig_size_constant_matches_real_signature():
    assert len(Signer().sign(b"x")) == SIG_SIZE


def test_client_packet_size_and_roundtrip():
    msg = pad_telemetry(b"Heart rate: 78")
    assert len(msg) == TELEMETRY_SIZE
    pkt = ClientPacket(msg, make_meta().to_bytes(), b"\x01" * 2420, b"\x02" * 32)
    raw = pkt.to_bytes()
    print(f"\nphase 1 packet: {len(raw)} bytes")
    assert len(raw) == CLIENT_PACKET_SIZE == 2584
    assert ClientPacket.from_bytes(raw) == pkt
    assert pkt.signed_content() == msg + pkt.meta
    assert pkt.metadata.seq == 7


def test_edge_packet_size_and_roundtrip():
    pkt = EdgePacket(b"\x01" * 768, b"\x02" * 32, b"\x03" * 12,
                     b"\x04" * 2584, b"\x05" * 16, b"\x06" * 2420)
    raw = pkt.to_bytes()
    print(f"\nphase 2 packet: {len(raw)} bytes")
    assert len(raw) == EDGE_PACKET_SIZE == 5832
    assert EdgePacket.from_bytes(raw) == pkt
    assert len(pkt.signed_content()) == 5832 - 2420
    assert CLIENT_PACKET_SIZE + EDGE_PACKET_SIZE == 8416


def test_wrong_sizes_rejected():
    with pytest.raises(ValueError):
        ClientPacket.from_bytes(b"\x00" * 100)
    with pytest.raises(ValueError):
        EdgePacket.from_bytes(b"\x00" * 100)
    with pytest.raises(ValueError):
        pad_telemetry(b"x" * 101)