"""Benchmark harness for the PQ-IoMT prototype (timing, resources, packet sizes)."""
import argparse
import json
import os
import resource
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import psutil

from src.crypto.hashing import hmac_sha3_256, hmac_verify, sha3_256
from src.crypto.kdf import derive_aes_key
from src.crypto.kem import KEMKeyPair, encapsulate
from src.crypto.signature import Signer, verify
from src.crypto.symmetric import AESGCMCipher
from src.entities.client import ClientNode
from src.entities.qses import QSESNode
from src.entities.server import MedicalServerNode
from src.protocol.messages import CLIENT_PACKET_SIZE, EDGE_PACKET_SIZE

WARMUP = 10
PAPER_CLIENT_MS = 1.87                       # from the paper's Table II (client side)
PAPER_SIZES = (2584, 5832, 8416)             # phase 1, phase 2, total


# ---------------------------------------------------------------- helpers
def summarize(samples):
    s = sorted(samples)
    return {
        "mean": statistics.mean(s),
        "median": statistics.median(s),
        "stdev": statistics.stdev(s) if len(s) > 1 else 0.0,
        "p95": s[int(0.95 * (len(s) - 1))],
        "min": s[0],
    }


def time_calls(fn, inputs, warmup=WARMUP):
    """Call fn(x) for each input. Returns (timings_ms excluding warmup, all outputs)."""
    samples, outputs = [], []
    for i, x in enumerate(inputs):
        t0 = time.perf_counter()
        out = fn(x)
        dt = (time.perf_counter() - t0) * 1000
        outputs.append(out)
        if i >= warmup:
            samples.append(dt)
    return samples, outputs


def measure(fn, inputs):
    """time_calls plus CPU% and RSS for the phase."""
    proc = psutil.Process()
    cpu0 = sum(proc.cpu_times()[:2])         # user + system seconds
    wall0 = time.perf_counter()
    samples, outputs = time_calls(fn, inputs)
    wall = time.perf_counter() - wall0
    cpu = sum(proc.cpu_times()[:2]) - cpu0
    result = {
        "stats": summarize(samples),
        "cpu_pct": 100 * cpu / wall,
        "rss_mb": proc.memory_info().rss / 1e6,
    }
    return result, outputs


def print_table(title, rows):
    print(f"\n{title}  (ms)")
    print(f"{'operation':<42}{'mean':>9}{'median':>9}{'p95':>9}{'stdev':>9}")
    for label, s in rows:
        print(f"{label:<42}{s['mean']:>9.3f}{s['median']:>9.3f}"
              f"{s['p95']:>9.3f}{s['stdev']:>9.3f}")


# ------------------------------------------------------------------- main
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=200,
                        help="measured iterations per operation (paper: 100-1000)")
    n = parser.parse_args().iterations
    total = n + WARMUP

    # ---- setup: one device, one QSES, one server ----
    server = MedicalServerNode(server_id=9)
    client = ClientNode(client_id=1, server_id=9, session_id=3, qses_nonce=222)
    qses = QSESNode(server.public_key, max_age_ms=10 * 60 * 1000)
    qses.register_client(1, client.public_key)
    server.trust_qses(qses.public_key)
    server.register_client(1, client.public_key, client.hmac_key, 222)

    # ---- 1. end-to-end per entity (outputs of one feed the next) ----
    telemetry = b"Heart rate: 78"
    client_res, client_pkts = measure(client.create_signed_reading, [telemetry] * total)
    qses_res, edge_pkts = measure(qses.process_and_forward, client_pkts)
    server_res, _ = measure(server.receive_and_verify, edge_pkts)
    assert len(server.database) == total, "server did not accept every packet"

    print_table(f"End-to-end per entity, {n} iterations (+{WARMUP} warmup)", [
        ("Device: create_signed_reading", client_res["stats"]),
        ("QSES: process_and_forward", qses_res["stats"]),
        ("Server: receive_and_verify", server_res["stats"]),
    ])

    # ---- 2. per-operation breakdown ----
    kem = KEMKeyPair()
    signer = Signer()
    content = os.urandom(132)                       # M || meta
    digest = sha3_256(content)
    sig = signer.sign(digest)
    ct, ss = encapsulate(kem.public_key)
    salt = os.urandom(32)
    cipher = AESGCMCipher(derive_aes_key(ss, salt))
    payload = os.urandom(CLIENT_PACKET_SIZE)        # what QSES encrypts
    iv, c, tag = cipher.encrypt_detached(payload)
    mac_key = os.urandom(32)
    mac = hmac_sha3_256(mac_key, content)

    ops = [
        ("Device+QSES: SHA3-256 (132 B)",       lambda _: sha3_256(content)),
        ("Device+QSES: ML-DSA-44 sign",         lambda _: signer.sign(digest)),
        ("Device: HMAC-SHA3-256",               lambda _: hmac_sha3_256(mac_key, content)),
        ("QSES+Server: ML-DSA-44 verify",       lambda _: verify(digest, sig, signer.public_key)),
        ("QSES: ML-KEM-512 encapsulate",        lambda _: encapsulate(kem.public_key)),
        ("QSES+Server: HKDF-SHA256",            lambda _: derive_aes_key(ss, salt)),
        ("QSES: AES-256-GCM encrypt (2584 B)",  lambda _: cipher.encrypt_detached(payload)),
        ("Server: ML-KEM-512 decapsulate",      lambda _: kem.decapsulate(ct)),
        ("Server: AES-256-GCM decrypt (2584 B)", lambda _: cipher.decrypt_detached(iv, c, tag)),
        ("Server: HMAC verify",                 lambda _: hmac_verify(mac_key, content, mac)),
    ]
    micro_rows = []
    for label, fn in ops:
        samples, _ = time_calls(fn, [None] * total)
        micro_rows.append((label, summarize(samples)))
    print_table("Per-operation breakdown", micro_rows)

    # ---- 3. resources ----
    peak_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024   # KB on Linux
    print("\nResources (all three entities share ONE process here)")
    print(f"{'phase':<20}{'CPU %':>9}{'RSS MB':>10}")
    for label, res in (("device", client_res), ("QSES", qses_res), ("server", server_res)):
        print(f"{label:<20}{res['cpu_pct']:>9.1f}{res['rss_mb']:>10.1f}")
    print(f"peak RSS of the process: {peak_mb:.1f} MB")

    # ---- 4. packet sizes ----
    p1, p2 = len(client_pkts[-1].to_bytes()), len(edge_pkts[-1].to_bytes())
    measured = (p1, p2, p1 + p2)
    print("\nPacket sizes (bytes)")
    for label, got, want in zip(("phase 1 (device->QSES)", "phase 2 (QSES->server)", "total"),
                                measured, PAPER_SIZES):
        print(f"{label:<26}{got:>8}   paper {want:>6}   {'OK' if got == want else 'MISMATCH'}")

    # ---- 5. paper comparison ----
    mean = client_res["stats"]["mean"]
    print(f"\nDevice time: measured {mean:.3f} ms vs paper ~{PAPER_CLIENT_MS} ms "
          f"({mean / PAPER_CLIENT_MS:.2f}x)")
    print("Add the paper's other Table II/III values to compare QSES and server.")

    # ---- save raw results ----
    out = {
        "iterations": n,
        "end_to_end": {"device": client_res, "qses": qses_res, "server": server_res},
        "operations": {label: s for label, s in micro_rows},
        "packet_sizes": dict(zip(("phase1", "phase2", "total"), measured)),
        "peak_rss_mb": peak_mb,
    }
    path = Path(__file__).with_name("results.json")
    path.write_text(json.dumps(out, indent=2))
    print(f"\nsaved {path}")

    for obj in (client, qses, server, kem, signer):
        obj.close()


if __name__ == "__main__":
    main()