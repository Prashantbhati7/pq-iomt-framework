"""
PQ-IoMT Comparison Benchmark
==============================
Compares the base paper implementation against the session-encrypted variant.

Base paper (demo-checkpoint.ipynb):  Sensor -> QSES plaintext (sign only)
Our fix (session_link_demo.ipynb):   Sensor -> QSES AES-256-GCM encrypted
                                     + ML-KEM-512 handshake once per session

Charts produced:
  chart1_per_reading_latency.png      - mean / p95 per entity
  chart2_amortized_overhead.png       - overhead per reading vs session length
  chart3_packet_sizes.png             - byte breakdown of each hop
  chart4_operation_breakdown.png      - per-operation timing (from results.json)
  chart5_cumulative_overhead.png      - cumulative bytes + time as #packets grows
  chart6_overhead_pct_vs_session.png  - overhead % vs session size
  chart7_summary_table.png            - summary table
  chart8_latency_distribution.png     - violin plots
"""

import json
import statistics
import sys
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.entities.client import ClientNode
from src.entities.qses import QSESNode
from src.entities.server import MedicalServerNode
from src.entities.secure_client import SecureClientNode
from src.entities.secure_qses import SecureQSESNode
from src.protocol.messages import CLIENT_PACKET_SIZE, EDGE_PACKET_SIZE
from src.protocol.secure_messages import LINK_PACKET_SIZE, NONCE_SIZE

OUT_DIR = Path(__file__).parent

# Palette (matching comparison_notebook.ipynb)
C_BASE   = "#064D80"
C_SECURE = "#F60C0C"
C_ACCENT = "#DE8D0A"
C_GREEN  = "#269118"
DARK_BG  = "#F7F7FA"
CARD_BG  = "#CFD2D2"
GRID_CLR = "#BA5BEA"
TEXT_CLR = "#050404"

plt.rcParams.update({
    "figure.facecolor": DARK_BG, "axes.facecolor": CARD_BG,
    "axes.edgecolor": GRID_CLR,  "axes.labelcolor": TEXT_CLR,
    "xtick.color": TEXT_CLR,     "ytick.color": TEXT_CLR,
    "text.color": TEXT_CLR,      "grid.color": GRID_CLR,
    "grid.linestyle": "--",      "grid.linewidth": 0.5,
    "legend.facecolor": CARD_BG, "legend.edgecolor": GRID_CLR,
    "legend.labelcolor": TEXT_CLR, "font.family": "DejaVu Sans",
})

TELEMETRY     = b"Heart rate: 78"
WARMUP        = 15
N_ITER        = 200
SESSION_SIZES = [1, 2, 5, 10, 20, 50, 100, 200, 500]


def summarize(samples):
    s = sorted(samples)
    n = len(s)
    return dict(mean=statistics.mean(s), median=statistics.median(s),
                stdev=statistics.stdev(s) if n > 1 else 0.0,
                p95=s[int(0.95*(n-1))], p5=s[int(0.05*(n-1))],
                min=s[0], max=s[-1])


def savefig(name):
    path = OUT_DIR / name
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=DARK_BG)
    plt.close()
    print(f"  -> saved {path.name}")


# ============================================================
# 1. BASE PAPER: measure end-to-end per entity
#    The QSES has sequence-number replay protection, so we must
#    use the same pipeline approach as benchmark.py:
#    pre-generate all packets, then measure each stage.
# ============================================================
print("=" * 60)
print(f"Building base-paper pipeline ({N_ITER+WARMUP} packets)...")

server_b = MedicalServerNode(server_id=9)
client_b = ClientNode(client_id=1, server_id=9, session_id=3, qses_nonce=222)
qses_b   = QSESNode(server_b.public_key, max_age_ms=10*60*1000)
qses_b.register_client(1, client_b.public_key)
server_b.trust_qses(qses_b.public_key)
server_b.register_client(1, client_b.public_key, client_b.hmac_key, 222)

total = N_ITER + WARMUP

# Stage 1: device creates packets
device_times = []
client_pkts  = []
for i in range(total):
    t0  = time.perf_counter()
    pkt = client_b.create_signed_reading(TELEMETRY)
    dt  = (time.perf_counter() - t0) * 1000
    client_pkts.append(pkt)
    if i >= WARMUP:
        device_times.append(dt)

# Stage 2: QSES processes each packet
qses_times = []
edge_pkts  = []
for i, pkt in enumerate(client_pkts):
    t0  = time.perf_counter()
    ep  = qses_b.process_and_forward(pkt)
    dt  = (time.perf_counter() - t0) * 1000
    edge_pkts.append(ep)
    if i >= WARMUP:
        qses_times.append(dt)

# Stage 3: server verifies
server_times = []
for i, ep in enumerate(edge_pkts):
    t0 = time.perf_counter()
    server_b.receive_and_verify(ep)
    dt = (time.perf_counter() - t0) * 1000
    if i >= WARMUP:
        server_times.append(dt)

base_device = summarize(device_times)
base_qses   = summarize(qses_times)
base_server = summarize(server_times)

print(f"  Device  sign:  mean={base_device['mean']:.3f} ms  p95={base_device['p95']:.3f} ms")
print(f"  QSES   fwd:   mean={base_qses['mean']:.3f} ms   p95={base_qses['p95']:.3f} ms")
print(f"  Server verify: mean={base_server['mean']:.3f} ms  p95={base_server['p95']:.3f} ms")


# ============================================================
# 2. SECURE VARIANT
# ============================================================
print(f"\nBuilding secure pipeline ({N_ITER+WARMUP} packets)...")

server_s = MedicalServerNode(server_id=9)
qses_s   = SecureQSESNode(server_s.public_key, max_age_ms=10*60*1000)
client_s = SecureClientNode(client_id=1, server_id=9, session_id=3,
                            qses_nonce=222, qses_public_key=qses_s.public_key)
qses_s.register_client(1, client_s.public_key)
server_s.trust_qses(qses_s.public_key)
server_s.register_client(1, client_s.public_key, client_s.hmac_key, 222)

# Handshake (once per session)
def do_handshake(q, c):
    cid, n_i, pk_kem, sig_d = c.begin_session()
    n_q, sid, ct, sig_q     = q.accept_session(cid, n_i, pk_kem, sig_d)
    c.complete_session(n_q, sid, ct, sig_q)
    return sid

do_handshake(qses_s, client_s)

sec_device_times = []
link_pkts        = []
for i in range(total):
    t0  = time.perf_counter()
    lp  = client_s.create_encrypted_reading(TELEMETRY)
    dt  = (time.perf_counter() - t0) * 1000
    link_pkts.append(lp)
    if i >= WARMUP:
        sec_device_times.append(dt)

sec_qses_times = []
sec_edge_pkts  = []
for i, lp in enumerate(link_pkts):
    t0 = time.perf_counter()
    ep = qses_s.receive_from_sensor(lp)
    dt = (time.perf_counter() - t0) * 1000
    sec_edge_pkts.append(ep)
    if i >= WARMUP:
        sec_qses_times.append(dt)

sec_server_times = []
for i, ep in enumerate(sec_edge_pkts):
    t0 = time.perf_counter()
    server_s.receive_and_verify(ep)
    dt = (time.perf_counter() - t0) * 1000
    if i >= WARMUP:
        sec_server_times.append(dt)

secure_device = summarize(sec_device_times)
secure_qses   = summarize(sec_qses_times)
secure_server = summarize(sec_server_times)

print(f"  Device  enc+sign: mean={secure_device['mean']:.3f} ms  p95={secure_device['p95']:.3f} ms")
print(f"  QSES   dec+fwd:  mean={secure_qses['mean']:.3f} ms   p95={secure_qses['p95']:.3f} ms")
print(f"  Server verify:    mean={secure_server['mean']:.3f} ms  p95={secure_server['p95']:.3f} ms")


# ============================================================
# 3. HANDSHAKE COST (isolated)
# ============================================================
print("\nBenchmarking handshake (isolated)...")
hs_samples = []
hs_n = 60 + WARMUP
for i in range(hs_n):
    sv = MedicalServerNode(server_id=9)
    qs = SecureQSESNode(sv.public_key, max_age_ms=10*60*1000)
    cl = SecureClientNode(client_id=1, server_id=9, session_id=3,
                          qses_nonce=222, qses_public_key=qs.public_key)
    qs.register_client(1, cl.public_key)
    t0 = time.perf_counter()
    cid, n_i, pk_kem, sig_d = cl.begin_session()
    n_q, sid, ct, sig_q     = qs.accept_session(cid, n_i, pk_kem, sig_d)
    cl.complete_session(n_q, sid, ct, sig_q)
    dt = (time.perf_counter() - t0) * 1000
    if i >= WARMUP:
        hs_samples.append(dt)

hs_stats = summarize(hs_samples)
print(f"  Handshake: mean={hs_stats['mean']:.3f} ms  p95={hs_stats['p95']:.3f} ms")


# ============================================================
# 4. Derived numbers
# ============================================================
delta_device_ms = secure_device['mean'] - base_device['mean']
delta_qses_ms   = secure_qses['mean']   - base_qses['mean']
handshake_ms    = hs_stats['mean']

amortized = [(handshake_ms/n + delta_device_ms + delta_qses_ms) for n in SESSION_SIZES]

base_link_size   = CLIENT_PACKET_SIZE   # 2584
secure_link_size = LINK_PACKET_SIZE     # 2616
link_overhead    = secure_link_size - base_link_size   # 32
edge_size        = EDGE_PACKET_SIZE                    # 5832

nonce_sz     = NONCE_SIZE   # 16
kem_pk_sz    = 800
sig_sz       = 2420
ct_sz        = 768
hello_bytes  = 4 + nonce_sz + kem_pk_sz + sig_sz   # 3240
reply_bytes  = nonce_sz + 4 + ct_sz + sig_sz        # 3208
hs_bytes     = hello_bytes + reply_bytes             # 6448

print(f"\nPacket sizes (Sensor->QSES):")
print(f"  Base  : {base_link_size} B/reading")
print(f"  Secure: {secure_link_size} B/reading  (+{link_overhead} B, +{link_overhead/base_link_size*100:.1f}%)")
print(f"  Handshake (one-off): {hs_bytes} B ({hello_bytes}+{reply_bytes})")


# ============================================================
# 5. Load existing results.json
# ============================================================
with open(ROOT / "benchmarks" / "results.json") as f:
    paper = json.load(f)

ops_data  = paper["operations"]
pb_device = paper["end_to_end"]["device"]["stats"]
pb_qses   = paper["end_to_end"]["qses"]["stats"]
pb_server = paper["end_to_end"]["server"]["stats"]


# ============================================================
# CHARTS
# ============================================================
print("\nGenerating charts...")

# ── Chart 1: Per-reading latency (3 entities, both variants) ──────────────
fig, axes = plt.subplots(1, 3, figsize=(16, 6))
fig.suptitle("Per-Reading Latency: Base Paper vs Session-Key Variant",
             fontsize=16, fontweight="bold", color=TEXT_CLR, y=1.02)

roles = ["Device (Sensor)", "QSES (Edge)", "Medical Server"]
bmeans = [base_device['mean'],   base_qses['mean'],   base_server['mean']]
bp95s  = [base_device['p95'],    base_qses['p95'],    base_server['p95']]
smeans = [secure_device['mean'], secure_qses['mean'], secure_server['mean']]
sp95s  = [secure_device['p95'],  secure_qses['p95'],  secure_server['p95']]

for ax, role, bm, bp, sm, sp in zip(axes, roles, bmeans, bp95s, smeans, sp95s):
    w = 0.55
    bb = ax.bar([0], [bm], w, color=C_BASE,   label="Base (plaintext)", zorder=3)
    bs = ax.bar([1], [sm], w, color=C_SECURE, label="Secure (AES-GCM)", zorder=3)
    ax.hlines(bp, -0.3, 0.3, colors=C_ACCENT, linewidths=2, linestyles="--", zorder=4)
    ax.hlines(sp,  0.7, 1.3, colors=C_ACCENT, linewidths=2, linestyles="--", zorder=4)
    pct = (sm/bm - 1)*100 if bm > 0 else 0
    ax.text(0.5, max(bm, sm)*1.08, f"Δ {sm-bm:+.3f} ms\n({pct:+.1f}%)",
            ha="center", va="bottom", fontsize=9, color=C_ACCENT, fontweight="bold")
    ax.set_xticks([0,1]); ax.set_xticklabels(["Base","Secure"], fontsize=10)
    ax.set_ylabel("Latency (ms)", fontsize=9)
    ax.set_title(role, fontsize=11, fontweight="bold", color=TEXT_CLR)
    ax.grid(axis="y", zorder=0)
    ax.set_ylim(0, max(bm,sm)*1.3)
    for bar, v in [(bb[0],bm),(bs[0],sm)]:
        ax.text(bar.get_x()+bar.get_width()/2, v+v*0.02, f"{v:.3f}",
                ha="center", va="bottom", fontsize=8, color=TEXT_CLR)
    pp = mpatches.Patch(color=C_ACCENT, linestyle="--", label="p95", fill=False)
    ax.legend(handles=[bb[0],bs[0],pp], fontsize=8)

plt.tight_layout()
savefig("chart1_per_reading_latency.png")


# ── Chart 2: Amortized overhead vs session size ───────────────────────────
fig, ax = plt.subplots(figsize=(12, 6))
fig.suptitle("Amortized Overhead Per Reading vs Session Length",
             fontsize=15, fontweight="bold", color=TEXT_CLR)

floor = [delta_device_ms + delta_qses_ms] * len(SESSION_SIZES)
ax.plot(SESSION_SIZES, amortized, "o-",  color=C_SECURE, lw=2.5, ms=7,
        label="Total overhead (AES-GCM + amortised handshake)")
ax.plot(SESSION_SIZES, floor,     "s--", color=C_BASE,   lw=2,   ms=5,
        label="Per-reading AES-GCM overhead only (floor)")
ax.fill_between(SESSION_SIZES, floor, amortized, alpha=0.18, color=C_ACCENT,
                label="Handshake cost being amortised")
ax.set_xscale("log")
ax.set_xticks(SESSION_SIZES); ax.set_xticklabels([str(x) for x in SESSION_SIZES])
ax.set_xlabel("Readings per Session", fontsize=12)
ax.set_ylabel("Additional Latency per Reading (ms)", fontsize=12)
ax.legend(fontsize=10); ax.grid(True, which="both")
for n, ov in zip(SESSION_SIZES, amortized):
    if n in (1, 10, 100, 500):
        ax.annotate(f"{ov:.3f} ms", xy=(n, ov), xytext=(n*1.25, ov+0.005),
                    fontsize=8, color=TEXT_CLR,
                    arrowprops=dict(arrowstyle="->", color=TEXT_CLR, lw=0.8))
plt.tight_layout()
savefig("chart2_amortized_overhead.png")


# ── Chart 3: Packet sizes ─────────────────────────────────────────────────
fig, axes = plt.subplots(1, 2, figsize=(14, 6))
fig.suptitle("Packet Size Breakdown: Sensor -> QSES Link",
             fontsize=15, fontweight="bold", color=TEXT_CLR)

ax = axes[0]
bparts  = [100, 32, 2420, 32]
sparts  = [2584, 4, 12, 16]
bcols   = ["#5BB450","#4C9ED9","#E05C5C","#F5A623"]
scols   = ["#555577","#4C9ED9","#F5A623","#E05C5C"]
blabels = ["Telemetry\n(100 B)","Metadata\n(32 B)","ML-DSA Sig\n(2420 B)","HMAC\n(32 B)"]
slabels = ["Encrypted Pkt\n(2584 B)","Session ID\n(4 B)","IV\n(12 B)","GCM Tag\n(16 B)"]
bb, sb = 0, 0
for v, c in zip(bparts, bcols):
    ax.bar(0, v, 0.5, bottom=bb, color=c, zorder=3)
    if v > 50: ax.text(0, bb+v/2, f"{v} B", ha="center", va="center",
                       fontsize=8, color="white", fontweight="bold")
    bb += v
for v, c in zip(sparts, scols):
    ax.bar(1, v, 0.5, bottom=sb, color=c, zorder=3)
    if v > 50: ax.text(1, sb+v/2, f"{v} B", ha="center", va="center",
                       fontsize=8, color="white", fontweight="bold")
    sb += v
ax.set_xticks([0,1])
ax.set_xticklabels([f"Base\n({base_link_size} B)", f"Secure\n({secure_link_size} B)"], fontsize=11)
ax.set_ylabel("Bytes", fontsize=11)
ax.set_title("Per-Reading Packet Structure", fontsize=12, color=TEXT_CLR)
ax.grid(axis="y", zorder=0)
ax.set_ylim(0, max(base_link_size, secure_link_size)*1.12)
ax.annotate("", xy=(1.3, secure_link_size), xytext=(1.3, base_link_size),
            arrowprops=dict(arrowstyle="<->", color=C_ACCENT, lw=1.5))
ax.text(1.38, (base_link_size+secure_link_size)/2,
        f"+{link_overhead} B\n(+{link_overhead/base_link_size*100:.1f}%)",
        va="center", fontsize=9, color=C_ACCENT, fontweight="bold")

ax2 = axes[1]
labels2 = ["Sensor->QSES\n(Base)","Sensor->QSES\n(Secure)","QSES->Server\n(both)"]
sizes2  = [base_link_size, secure_link_size, edge_size]
cols2   = [C_BASE, C_SECURE, C_GREEN]
bars2   = ax2.bar(labels2, sizes2, color=cols2, width=0.5, zorder=3)
for bar, sz in zip(bars2, sizes2):
    ax2.text(bar.get_x()+bar.get_width()/2, sz+30, f"{sz:,} B",
             ha="center", va="bottom", fontsize=10, color=TEXT_CLR, fontweight="bold")
ax2.set_ylabel("Bytes", fontsize=11)
ax2.set_title("All Packet Sizes per Reading", fontsize=12, color=TEXT_CLR)
ax2.grid(axis="y", zorder=0); ax2.set_ylim(0, edge_size*1.15)
plt.tight_layout()
savefig("chart3_packet_sizes.png")


# ── Chart 4: Per-operation breakdown (results.json) ───────────────────────
fig, ax = plt.subplots(figsize=(14, 7))
fig.suptitle("Per-Operation Timing — Base Paper (from benchmarks/results.json)",
             fontsize=14, fontweight="bold", color=TEXT_CLR)
op_names  = list(ops_data.keys())
op_means  = [ops_data[k]["mean"]  for k in op_names]
op_p95s   = [ops_data[k]["p95"]   for k in op_names]
op_stdevs = [ops_data[k]["stdev"] for k in op_names]

def op_color(n):
    if "Device" in n:      return C_BASE
    if "QSES+Server" in n: return C_ACCENT
    if "QSES" in n:        return C_SECURE
    if "Server" in n:      return C_GREEN
    return "#AAAAAA"

y = np.arange(len(op_names))
bars = ax.barh(y, op_means, color=[op_color(n) for n in op_names], height=0.55, zorder=3)
ax.errorbar(op_means, y, xerr=op_stdevs, fmt="none",
            ecolor=TEXT_CLR, elinewidth=1, capsize=4, zorder=4)
for i, p in enumerate(op_p95s):
    ax.plot(p, i, "D", color=C_ACCENT, markersize=5, zorder=5)
ax.set_yticks(y); ax.set_yticklabels(op_names, fontsize=9)
ax.set_xlabel("Time (ms)", fontsize=11); ax.grid(axis="x", zorder=0)
lh = [mpatches.Patch(color=C_BASE, label="Device"),
      mpatches.Patch(color=C_SECURE, label="QSES"),
      mpatches.Patch(color=C_GREEN, label="Server"),
      mpatches.Patch(color=C_ACCENT, label="QSES+Server"),
      plt.Line2D([0],[0], marker="D", color=C_ACCENT, linestyle="None", ms=5, label="p95")]
ax.legend(handles=lh, fontsize=9, loc="lower right")
for bar, v in zip(bars, op_means):
    ax.text(v+0.0005, bar.get_y()+bar.get_height()/2,
            f"{v:.4f} ms", va="center", fontsize=7.5, color=TEXT_CLR)
plt.tight_layout()
savefig("chart4_operation_breakdown.png")


# ── Chart 5: Cumulative overhead ──────────────────────────────────────────
fig, axes = plt.subplots(1, 2, figsize=(15, 6))
fig.suptitle("Cumulative Overhead as Packet Count Grows",
             fontsize=15, fontweight="bold", color=TEXT_CLR)

pr = np.arange(1, 501)
bby = pr * base_link_size
sby = pr * secure_link_size + hs_bytes

ax = axes[0]
ax.plot(pr, bby/1024, color=C_BASE,   lw=2, label="Base (bytes sent)")
ax.plot(pr, sby/1024, color=C_SECURE, lw=2, label="Secure (bytes sent)")
ax.fill_between(pr, bby/1024, sby/1024, alpha=0.2, color=C_ACCENT,
                label=f"Overhead (HS={hs_bytes} B once + {link_overhead} B/pkt)")
be = int(hs_bytes / link_overhead) if link_overhead > 0 else 200
ax.axvline(x=be, color=C_GREEN, ls=":", lw=1.5)
ylims = ax.get_ylim()
ax.text(be+4, ylims[0]+(ylims[1]-ylims[0])*0.12,
        f"HS amort.\n@ pkt {be}", fontsize=8, color=C_GREEN)
ax.set_xlabel("Number of Packets (Sensor->QSES)", fontsize=11)
ax.set_ylabel("Cumulative Bytes (KB)", fontsize=11)
ax.set_title("Cumulative Byte Cost", fontsize=12, color=TEXT_CLR)
ax.legend(fontsize=9); ax.grid(True)

bty = pr * base_device['mean']
sty = pr * secure_device['mean'] + hs_stats['mean']
ax2 = axes[1]
ax2.plot(pr, bty, color=C_BASE,   lw=2, label="Base cumulative time")
ax2.plot(pr, sty, color=C_SECURE, lw=2, label="Secure cumulative time")
ax2.fill_between(pr, bty, sty, alpha=0.2, color=C_ACCENT, label="Time overhead")
ax2.set_xlabel("Number of Packets (Sensor->QSES)", fontsize=11)
ax2.set_ylabel("Cumulative Device-side Time (ms)", fontsize=11)
ax2.set_title("Cumulative Time Cost (Device)", fontsize=12, color=TEXT_CLR)
ax2.legend(fontsize=9); ax2.grid(True)
plt.tight_layout()
savefig("chart5_cumulative_overhead.png")


# ── Chart 6: Overhead % vs session size ──────────────────────────────────
fig, ax = plt.subplots(figsize=(12, 5))
fig.suptitle("Handshake Cost Amortised — % Overhead vs Base",
             fontsize=14, fontweight="bold", color=TEXT_CLR)
base_sum = base_device['mean'] + base_qses['mean']
pct_ov = [(handshake_ms/n + delta_device_ms + delta_qses_ms)/base_sum*100
          for n in SESSION_SIZES]
ax.plot(SESSION_SIZES, pct_ov, "o-", color=C_SECURE, lw=2.5, ms=8)
floor_pct = (delta_device_ms + delta_qses_ms) / base_sum * 100
ax.axhline(y=floor_pct, color=C_BASE, ls="--", lw=1.5,
           label=f"AES-GCM floor = {floor_pct:.1f}%")
for n, p in zip(SESSION_SIZES, pct_ov):
    ax.text(n, p+0.4, f"{p:.1f}%", ha="center", va="bottom", fontsize=8, color=TEXT_CLR)
ax.set_xscale("log"); ax.set_xticks(SESSION_SIZES)
ax.set_xticklabels([str(x) for x in SESSION_SIZES])
ax.set_xlabel("Readings per Session", fontsize=12)
ax.set_ylabel("% Overhead vs Base (Device + QSES)", fontsize=12)
ax.legend(fontsize=10); ax.grid(True, which="both")
plt.tight_layout()
savefig("chart6_overhead_pct_vs_session_size.png")


# ── Chart 7: Summary table ────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(14, 5))
fig.patch.set_facecolor(DARK_BG); ax.set_facecolor(DARK_BG); ax.axis("off")

def dfmt(bm, sm):
    d = sm-bm; p = (sm/bm-1)*100 if bm > 0 else 0
    return f"{d:+.4f} ms ({p:+.1f}%)"

rows = [
    ["Device latency (mean)", f"{base_device['mean']:.4f} ms",
     f"{secure_device['mean']:.4f} ms", dfmt(base_device['mean'], secure_device['mean'])],
    ["Device latency (p95)",  f"{base_device['p95']:.4f} ms",
     f"{secure_device['p95']:.4f} ms",  dfmt(base_device['p95'],  secure_device['p95'])],
    ["QSES latency (mean)",   f"{base_qses['mean']:.4f} ms",
     f"{secure_qses['mean']:.4f} ms",   dfmt(base_qses['mean'],   secure_qses['mean'])],
    ["Server latency (mean)", f"{base_server['mean']:.4f} ms",
     f"{secure_server['mean']:.4f} ms", dfmt(base_server['mean'], secure_server['mean'])],
    ["Sensor->QSES pkt (per reading)", f"{base_link_size:,} B", f"{secure_link_size:,} B",
     f"+{link_overhead} B (+{link_overhead/base_link_size*100:.1f}%)"],
    ["QSES->Server pkt", f"{edge_size:,} B", f"{edge_size:,} B", "0 B (unchanged)"],
    ["Handshake (one-off)", "None",
     f"{hs_stats['mean']:.2f} ms / {hs_bytes:,} B",
     f"Amortised; @{int(hs_bytes/link_overhead)} pkts = break-even bytes"],
    ["Security: Sensor->QSES", "Plaintext (sign only)",
     "AES-256-GCM encrypted", "Confidentiality added"],
    ["Forward secrecy", "N/A", "Yes (ephemeral Kyber)", "sk_kem deleted post-HS"],
]
col_labels = ["Metric", "Base Paper", "Secure Variant", "Delta / Notes"]
t = ax.table(cellText=rows, colLabels=col_labels, cellLoc="center", loc="center")
t.auto_set_font_size(False); t.set_fontsize(8.5); t.scale(1, 2.05)
for (r, c), cell in t.get_celld().items():
    cell.set_facecolor(CARD_BG if r > 0 else "#6D9DD7")
    cell.set_edgecolor(GRID_CLR)
    cell.set_text_props(color=TEXT_CLR, fontsize=8.5)
    if r == 0: cell.set_text_props(fontweight="bold", fontsize=9.5)
    if r > 0 and c == 3:
        txt = rows[r-1][3]
        if "+" in txt and not any(x in txt for x in ["unchanged","Amort","added","deleted"]):
            cell.set_facecolor("#EE6E6E")
        elif any(x in txt for x in ["unchanged","0 B","added","deleted"]):
            cell.set_facecolor("#58A758")

ax.set_title("Comparison Summary", fontsize=14, fontweight="bold", color=TEXT_CLR, pad=18)
plt.tight_layout()
savefig("chart7_summary_table.png")


# ── Chart 8: Violin plots ─────────────────────────────────────────────────
fig, axes = plt.subplots(1, 3, figsize=(15, 6))
fig.suptitle("Latency Distribution: Base vs Secure (All Entities)",
             fontsize=14, fontweight="bold", color=TEXT_CLR)

pairs = [("Device", device_times, sec_device_times),
         ("QSES",   qses_times,   sec_qses_times),
         ("Server", server_times, sec_server_times)]

for ax, (name, bs, ss) in zip(axes, pairs):
    vp = ax.violinplot([bs, ss], positions=[0,1], showmedians=True, showextrema=True)
    for patch, col in zip(vp["bodies"], [C_BASE, C_SECURE]):
        patch.set_facecolor(col); patch.set_alpha(0.7)
    vp["cmedians"].set_color(C_ACCENT)
    for k in ("cbars","cmins","cmaxes"): vp[k].set_color(TEXT_CLR)
    ax.set_xticks([0,1]); ax.set_xticklabels(["Base","Secure"], fontsize=10)
    ax.set_ylabel("Latency (ms)", fontsize=9)
    ax.set_title(name, fontsize=11, fontweight="bold", color=TEXT_CLR)
    ax.grid(axis="y")
    ax.legend(handles=[mpatches.Patch(color=C_BASE,  alpha=0.7, label="Base"),
                       mpatches.Patch(color=C_SECURE,alpha=0.7, label="Secure")], fontsize=8)

plt.tight_layout()
savefig("chart8_latency_distribution.png")

print("\nAll charts saved to:", OUT_DIR)
print("Done.")
