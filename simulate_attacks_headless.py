"""
simulate_attacks_headless.py — Headless version of simulate_attacks.py.
Called by the FastAPI backend's /api/sim/start endpoint.
Does not require ENTER key press; runs immediately.
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

def load_cache():
    if not os.path.exists(CACHE_FILE):
        print("ERROR: verified_attacks.json not found. Run build_attack_cache.py first.")
        sys.exit(1)
    with open(CACHE_FILE, 'r') as f:
        rows = json.load(f)
    from collections import defaultdict
    buckets = defaultdict(list)
    for r in rows:
        buckets[r['_label']].append({k: r[k] for k in FEAT_COLS})
    return buckets

_write_lock = threading.Lock()

def _write_flow(flow_dict: dict):
    line = json.dumps(flow_dict) + '\n'
    with _write_lock:
        with open(INJECT_FILE, 'a', encoding='utf-8') as fh:
            fh.write(line)

def run_wave(label, flows, rate_per_sec=3.0):
    cap    = min(40, len(flows))
    delay  = 1.0 / rate_per_sec
    sample = random.sample(flows, cap)
    for flow in sample:
        _write_flow(flow)
        time.sleep(delay)

if __name__ == "__main__":
    buckets = load_cache()

    # Clear stale files
    for f in (INJECT_FILE, DONE_SIGNAL):
        if os.path.exists(f):
            try: os.remove(f)
            except OSError: pass

    rates   = {'DDoS': 3.0, 'Brute Force': 2.0, 'Port Scanning': 4.0, 'Web Attacks': 2.5}
    threads = []
    for cls, flows in buckets.items():
        rate = rates.get(cls, 3.0)
        t    = threading.Thread(target=run_wave, args=(cls, flows, rate), daemon=True)
        threads.append(t)

    for t in threads: t.start()
    for t in threads: t.join()

    with open(DONE_SIGNAL, 'w') as fh:
        fh.write('done')

    print("Simulation complete.")
