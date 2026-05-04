"""
AI-IDS Attack Simulator  v5  —  Real-Data Edition
===================================================
Uses ACTUAL verified attack flows from the CIC-IDS-2017 training dataset
(pre-extracted by build_attack_cache.py) so the trained model is guaranteed
to classify every injected flow as an attack with ≥ 80 % confidence.

Usage
-----
1.  python build_attack_cache.py          (one-time, ~10 min on first run)
2.  Start the IDS dashboard and click "▶ Start"
3.  python simulate_attacks.py  →  press ENTER
"""

import sys, os, json, time, random, threading

_DIR        = os.path.dirname(os.path.abspath(__file__))
INJECT_FILE = os.path.join(_DIR, "_inject_queue.jsonl")
DONE_SIGNAL = os.path.join(_DIR, "_inject_done.flag")
CACHE_FILE  = os.path.join(_DIR, "verified_attacks.json")

FEAT_COLS = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets',
    'Total Length of Fwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Fwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
    'Average Packet Size',
]

# ── Load verified attack cache ─────────────────────────────────────────────────

def load_cache():
    if not os.path.exists(CACHE_FILE):
        print()
        print("  ERROR: verified_attacks.json not found.")
        print("  Please run:  python build_attack_cache.py  first (takes ~10 min).")
        print()
        sys.exit(1)

    with open(CACHE_FILE, 'r') as f:
        rows = json.load(f)

    from collections import defaultdict
    buckets = defaultdict(list)
    for r in rows:
        buckets[r['_label']].append({k: r[k] for k in FEAT_COLS})

    print(f"  Loaded {len(rows)} verified attack flows:")
    for cls, items in sorted(buckets.items()):
        # Average confidence from cache
        confs = [r['_conf'] for r in rows if r['_label'] == cls]
        import numpy as np
        avg = np.mean(confs)
        print(f"    {cls:20s}: {len(items):3d} flows  (avg model confidence: {avg:.1%})")
    print()
    return buckets

# ── Injection helpers ──────────────────────────────────────────────────────────

_write_lock = threading.Lock()

def _write_flow(flow_dict: dict):
    line = json.dumps(flow_dict) + '\n'
    with _write_lock:
        with open(INJECT_FILE, 'a', encoding='utf-8') as fh:
            fh.write(line)

# ── Attack wave workers ────────────────────────────────────────────────────────

def run_wave(label: str, flows: list, rate_per_sec: float = 3.0,
             counter: dict = None, counter_lock=None):
    """
    Inject up to 40 flows from `flows` at `rate_per_sec` flows/s.
    Capped at 40 to keep the run short (~10-20 s per class).
    """
    cap     = min(40, len(flows))
    delay   = 1.0 / rate_per_sec
    sample  = random.sample(flows, cap)
    n       = 0
    for flow in sample:
        _write_flow(flow)
        n += 1
        if counter is not None and counter_lock is not None:
            with counter_lock:
                counter[label] = counter.get(label, 0) + 1
        time.sleep(delay)
    print(f"    [{label}]  Done — {n} flows injected.")

# ── Main ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║   🛠   AI-IDS Attack Simulator  v5  — Real-Data Edition  ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()
    print("  Every injected flow is a REAL sample from CIC-IDS-2017,")
    print("  verified to be classified as an attack at ≥80% confidence.")
    print()

    buckets = load_cache()

    print("  HOW TO USE:")
    print("  1. Ensure your React frontend (npm run dev) and FastAPI backend are running.")
    print("  2. Start the Engine from the dashboard.")
    print("  3. Come back here and press ENTER.")
    print()
    try:
        input("  Press ENTER when the dashboard is live ...")
    except KeyboardInterrupt:
        sys.exit(0)

    # Clear stale files
    for f in (INJECT_FILE, DONE_SIGNAL):
        if os.path.exists(f):
            try: os.remove(f)
            except OSError: pass

    print()
    print("  ▶ Injecting attacks (all classes simultaneously) ...")
    print("    Watch your IDS dashboard for real-time detections!")
    print()

    counter      = {}
    counter_lock = threading.Lock()

    threads = []
    # Slower, controlled rate so the queue stays small
    rates = {'DDoS': 3.0, 'Brute Force': 2.0, 'Port Scanning': 4.0, 'Web Attacks': 2.5}
    for cls, flows in buckets.items():
        rate = rates.get(cls, 3.0)
        t = threading.Thread(
            target=run_wave,
            args=(cls, flows, rate, counter, counter_lock),
            daemon=True,
        )
        threads.append(t)

    for t in threads: t.start()

    # Live progress while attacks are running
    while any(t.is_alive() for t in threads):
        with counter_lock:
            snap = dict(counter)
        parts = "  |  ".join(f"{k}: {v}" for k, v in sorted(snap.items()))
        print(f"\r  Injected so far — {parts}          ", end='', flush=True)
        time.sleep(1.0)

    for t in threads: t.join()

    print()
    print()

    # Write done signal so dashboard can show "simulation complete"
    with open(DONE_SIGNAL, 'w') as fh:
        fh.write('done')

    total = sum(counter.values())
    print(f"  ✔  Simulation complete!  {total} verified attack flows injected.")
    print("     Check your AI-IDS Dashboard — alerts should be visible!")
    print()
