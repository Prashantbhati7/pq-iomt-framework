"""
Walk one telemetry reading through Device -> QSES (edge) -> Medical Server,
then run three attack scenarios against the same network.

Run:
    python scripts/simulate.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.entities.client import ClientNode
from src.entities.qses import QSESNode
from src.entities.server import MedicalServerNode
from src.protocol.errors import MaliciousEdgeError, ProtocolError
from src.protocol.messages import ClientPacket, EdgePacket


def hexpreview(data: bytes, n: int = 16) -> str:
    h = data[:n].hex()
    return f"{h}... ({len(data)} bytes total)" if len(data) > n else f"{h} ({len(data)} bytes)"


def section(title: str):
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


def step(label: str, detail: str = ""):
    print(f"  -> {label}" + (f": {detail}" if detail else ""))


def ok(label: str):
    print(f"  [OK] {label}")


def rejected(label: str, err: Exception):
    print(f"  [REJECTED] {label}: {err}")


def build_network():
    server = MedicalServerNode(server_id=9)
    client = ClientNode(client_id=1, server_id=9, session_id=3, qses_nonce=222)
    qses = QSESNode(server.public_key)

    qses.register_client(client.client_id, client.public_key)
    server.trust_qses(qses.public_key)
    server.register_client(client.client_id, client.public_key,
                           client.hmac_key, client.qses_nonce)
    return server, client, qses


def happy_path(client, qses, server, telemetry: bytes):
    section("PHASE 1 -- IoMT Device signs the reading")
    print(f"  telemetry: {telemetry!r}")
    pkt = client.create_signed_reading(telemetry)
    m = pkt.metadata
    step("padded message", hexpreview(pkt.message))
    step("metadata", f"client_id={m.client_id} seq={m.seq} "
                     f"session_id={m.session_id} server_id={m.server_id}")
    step("signature (ML-DSA-44)", hexpreview(pkt.signature))
    step("hmac (SHA3-256)", hexpreview(pkt.hmac))
    step("packet sent in the clear to QSES", hexpreview(pkt.to_bytes()))

    section("PHASE 2 -- QSES (edge) processes the packet")
    step("1. checking client is registered, timestamp fresh, seq not replayed")
    step("2. verifying device signature")
    step("3. encapsulating against the server's ML-KEM-512 public key")
    step("4. deriving AES-256 key with HKDF")
    step("5. encrypting the full device packet with AES-256-GCM")
    step("6. signing the bundle with QSES's ML-DSA-44 key")
    out = qses.process_and_forward(pkt)
    ok("all checks passed")
    step("kem ciphertext", hexpreview(out.kem_ciphertext))
    step("salt / iv / tag", f"{len(out.salt)}B / {len(out.iv)}B / {len(out.tag)}B")
    step("encrypted device packet", hexpreview(out.ciphertext))
    step("QSES signature", hexpreview(out.signature))
    step("packet sent to Medical Server", hexpreview(out.to_bytes()))
    assert telemetry not in out.to_bytes(), "leak!"
    ok(f"plaintext '{telemetry.decode()}' does not appear anywhere in the wire bytes")

    section("PHASE 3 -- Medical Server verifies and stores")
    step("1. verifying QSES transport signature")
    step("2. decapsulating shared secret, deriving AES key, decrypting")
    step("3. checking server_id, QSES nonce, device nonce, sequence number")
    step("4. verifying device's end-to-end signature")
    step("5. verifying HMAC (independent of QSES)")
    stored = server.receive_and_verify(out)
    ok("all checks passed, reading stored")
    step("stored reading", f"client={stored.client_id} seq={stored.seq} "
                           f"message={stored.message.rstrip(bytes(1))!r}")
    return pkt, out


def attack_replay(server, out):
    section("ATTACK 1 -- Replaying a captured packet")
    print("  an attacker resends the exact same Phase-2 packet")
    try:
        server.receive_and_verify(out)
        print("  !! replay was NOT caught (bug)")
    except ProtocolError as e:
        rejected("replayed packet", e)


def attack_bit_flip(server, out):
    section("ATTACK 2 -- Flipping one bit in transit")
    print("  an attacker on the QSES<->Server link flips one ciphertext bit")
    bad_ct = bytes([out.ciphertext[0] ^ 1]) + out.ciphertext[1:]
    tampered = EdgePacket(out.kem_ciphertext, out.salt, out.iv, bad_ct,
                          out.tag, out.signature)
    try:
        server.receive_and_verify(tampered)
        print("  !! tampering was NOT caught (bug)")
    except ProtocolError as e:
        rejected("tampered packet", e)


def attack_malicious_edge(server, client, qses):
    section("ATTACK 3 -- A malicious/compromised QSES forges the HMAC field")
    print("  QSES never sees the device's hmac_key, so it cannot produce a")
    print("  valid HMAC if it tries to alter the reading before forwarding it")
    genuine = client.create_signed_reading(b"Heart rate: 78")
    forged = ClientPacket(genuine.message, genuine.meta, genuine.signature,
                          b"\x00" * 32)          # QSES corrupts the HMAC
    out = qses.process_and_forward(forged)       # QSES's own checks still pass
    try:
        server.receive_and_verify(out)
        print("  !! forged HMAC was NOT caught (bug)")
    except MaliciousEdgeError as e:
        rejected("forged HMAC", e)
        ok(f"server.qses_flagged = {server.qses_flagged}")


def main():
    server, client, qses = build_network()
    happy_path(client, qses, server, b"Heart rate: 78")

    out = qses.process_and_forward(client.create_signed_reading(b"SpO2: 98"))
    server.receive_and_verify(out)                # so replay/bit-flip attack a fresh packet

    attack_replay(server, out)
    attack_bit_flip(server, out)
    attack_malicious_edge(server, client, qses)

    section("SUMMARY")
    step("readings stored", str(len(server.database)))
    step("anomalies logged", str(server.anomalies))
    step("QSES flagged as malicious", str(server.qses_flagged))

    for obj in (client, qses, server):
        obj.close()


if __name__ == "__main__":
    main()