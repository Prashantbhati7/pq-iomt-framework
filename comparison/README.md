# PQ-IoMT: Base Paper vs Session-Key Variant — Comparison

This folder contains a benchmark script and charts that quantify the
**trade-off** introduced by encrypting the Sensor → QSES link with a
per-session AES key derived via an ML-KEM-512 handshake.

---

## Background

| | Base Paper (`demo-checkpoint.ipynb`) | Secure Variant (`session_link_demo.ipynb`) |
|---|---|---|
| **Sensor → QSES** | Plaintext (sign + HMAC only) | AES-256-GCM encrypted |
| **QSES → Server** | ML-KEM + AES-256-GCM + QSES sign | _Same_ (unchanged) |
| **Session setup** | None | ML-KEM-512 handshake (once per session) |
| **Confidentiality** | None on the first hop | Full on first hop |
| **Forward secrecy** | N/A | Yes — ephemeral Kyber key deleted after HS |

---

## Running

```bash
cd /path/to/pq-iomt-framework
source myvenv/bin/activate
python comparison/comparison_benchmark.py
```

Adjust `N_ITER` (default 200) and `SESSION_SIZES` at the top of the script
to control benchmark depth.

---

## Charts

| File | What it shows |
|---|---|
| `chart1_per_reading_latency.png` | Mean + p95 latency per entity, both variants |
| `chart2_amortized_overhead.png` | Overhead per reading as session length grows |
| `chart3_packet_sizes.png` | Byte breakdown of Sensor→QSES and all hops |
| `chart4_operation_breakdown.png` | Per-operation timing from `benchmarks/results.json` |
| `chart5_cumulative_overhead.png` | Total bytes + time as packet count grows (1–500) |
| `chart6_overhead_pct_vs_session_size.png` | Overhead expressed as % vs base |
| `chart7_summary_table.png` | Side-by-side summary table |
| `chart8_latency_distribution.png` | Violin plots showing distribution shape |

---

## Key Numbers (representative run)

| Metric | Base | Secure | Delta |
|---|---|---|---|
| Device latency | ~0.08 ms | ~0.083 ms | +~0.003 ms |
| QSES latency | ~0.14 ms | ~0.146 ms | +~0.006 ms |
| Server latency | ~0.10 ms | ~0.097 ms | ~0 (unchanged) |
| Sensor→QSES packet | 2 584 B | 2 616 B | **+32 B (+1.2%)** |
| QSES→Server packet | 5 832 B | 5 832 B | 0 (unchanged) |
| Handshake (one-off) | — | ~0.27 ms / 6 448 B | Amortised |

### Break-even point

The 6 448-byte handshake adds 32 extra bytes × N readings over the session.
The handshake byte cost is paid off after **~202 packets** (6448 / 32).
In terms of time, even a 1-packet session costs only ~0.27 ms extra for the
full handshake — negligible for any realistic IoMT reading interval (≥ 1 s).

