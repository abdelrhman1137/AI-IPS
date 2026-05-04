"""
build_attack_cache.py  —  One-time cache builder for AI-IDS Attack Simulator
=============================================================================
Scans all CIC-IDS-2017 CSV files in the current directory, runs every attack
flow through the trained RF+XGBoost ensemble model, and saves those that are
classified as attacks with >= 80% confidence into verified_attacks.json.

The simulator (simulate_attacks.py) reads this cache so every injected flow
is GUARANTEED to trigger the IDS detector.

Usage
-----
    python build_attack_cache.py

Expected files in the same directory:
  • trained_ids_model.pkl
  • scaler.pkl
  • label_map.pkl
  • One or more CIC-IDS-2017 *.csv files (e.g. Friday-WorkingHours-*.csv)

Output
------
  • verified_attacks.json   — list of high-confidence attack flow dicts
"""

import os, sys, json, glob, warnings
import numpy as np
import pandas as pd
import joblib

warnings.filterwarnings("ignore")

# ── Paths ──────────────────────────────────────────────────────────────────────
_DIR       = os.path.dirname(os.path.abspath(__file__))
MODEL_FILE = os.path.join(_DIR, "trained_ids_model.pkl")
SCALER_FILE= os.path.join(_DIR, "scaler.pkl")
LMAP_FILE  = os.path.join(_DIR, "label_map.pkl")
OUT_FILE   = os.path.join(_DIR, "verified_attacks.json")

# Features the model was trained on (must match train_model.py & network_receptor.py)
FEAT_COLS = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets',
    'Total Length of Fwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Fwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
    'Average Packet Size',
]

# Minimum model confidence to include a flow in the cache
MIN_CONF = 0.80

# ── Label normalisation (matches train_model.py) ───────────────────────────────
LABEL_MAP_RAW = {
    "BENIGN":                   "Normal Traffic",
    "DoS Hulk":                 "DoS",
    "DoS GoldenEye":            "DoS",
    "DoS slowloris":            "DoS",
    "DoS Slowhttptest":         "DoS",
    "Heartbleed":               "DoS",
    "DDoS":                     "DDoS",
    "FTP-Patator":              "Brute Force",
    "SSH-Patator":              "Brute Force",
    "Web Attack \u2013 Brute Force":  "Brute Force",
    "Web Attack \u2013 XSS":          "Web Attacks",
    "Web Attack \u2013 Sql Injection": "Web Attacks",
    "PortScan":                 "Port Scanning",
    "Bot":                      "Botnet",
    "Infiltration":             "Other Exploit",
}

def normalise_label(raw: str) -> str:
    raw = raw.strip()
    return LABEL_MAP_RAW.get(raw, raw)


# ── Load model artefacts ───────────────────────────────────────────────────────
def load_model():
    for path, name in [(MODEL_FILE, "trained_ids_model.pkl"),
                       (SCALER_FILE, "scaler.pkl"),
                       (LMAP_FILE,   "label_map.pkl")]:
        if not os.path.exists(path):
            print(f"\n  ERROR: {name} not found.")
            print("  Please run  python train_model.py  first.\n")
            sys.exit(1)

    model     = joblib.load(MODEL_FILE)
    scaler    = joblib.load(SCALER_FILE)
    label_map = joblib.load(LMAP_FILE)          # int -> class string
    return model, scaler, label_map


# ── Find CSV files ─────────────────────────────────────────────────────────────
def find_csvs() -> list:
    csvs = glob.glob(os.path.join(_DIR, "*.csv"))
    if not csvs:
        print("\n  ERROR: No CSV files found in", _DIR)
        print("  Download CIC-IDS-2017 CSVs and place them here.\n")
        sys.exit(1)
    return csvs


# ── Process one CSV ────────────────────────────────────────────────────────────
def process_csv(path: str, model, scaler, label_map: dict,
                results: list, seen: int) -> int:
    fname = os.path.basename(path)
    print(f"  Reading {fname} …", end=" ", flush=True)

    try:
        df = pd.read_csv(path, encoding="utf-8", low_memory=False)
    except Exception as exc:
        print(f"SKIP ({exc})")
        return seen

    # Normalise column names
    df.columns = df.columns.str.strip()

    # Keep only rows that have all feature columns
    missing = [c for c in FEAT_COLS + [" Label"] if c not in df.columns]
    label_col = None
    for candidate in [" Label", "Label", "label"]:
        if candidate in df.columns:
            label_col = candidate
            break

    if label_col is None or any(c not in df.columns for c in FEAT_COLS):
        print("SKIP (missing columns)")
        return seen

    # Drop BENIGN rows early to save memory
    df[label_col] = df[label_col].astype(str).str.strip()
    df = df[df[label_col] != "BENIGN"].copy()
    if df.empty:
        print("0 attack rows, skipping.")
        return seen

    # Extract features
    try:
        X = df[FEAT_COLS].apply(pd.to_numeric, errors="coerce")
    except Exception as exc:
        print(f"SKIP (feature error: {exc})")
        return seen

    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    X = X.clip(-1e9, 1e9)

    labels_raw = df[label_col].tolist()
    added = 0

    # Batch predict (avoid memory blow-up for large files)
    BATCH = 5000
    for start in range(0, len(X), BATCH):
        xb  = X.iloc[start:start + BATCH].values
        lb  = labels_raw[start:start + BATCH]
        try:
            xs  = scaler.transform(xb)
            probs = model.predict_proba(xs)
        except Exception:
            continue

        for i, (prob_row, raw_lbl) in enumerate(zip(probs, lb)):
            idx  = int(np.argmax(prob_row))
            conf = float(prob_row[idx])
            pred = label_map.get(idx, "Unknown")
            norm = normalise_label(raw_lbl)

            # Only keep if model is confident AND it's a genuine attack
            if conf < MIN_CONF or pred == "Normal Traffic":
                continue

            row_dict = {col: float(xb[i, j]) for j, col in enumerate(FEAT_COLS)}
            row_dict["_label"] = pred
            row_dict["_conf"]  = round(conf, 4)
            row_dict["_raw"]   = norm
            results.append(row_dict)
            added += 1

        seen += len(xb)

    print(f"{added} verified attacks collected  ({seen:,} flows seen so far)")
    return seen


# ── Main ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║   AI-IDS  —  Verified Attack Cache Builder               ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()
    print(f"  Confidence threshold : {MIN_CONF:.0%}")
    print()

    model, scaler, label_map = load_model()
    csvs = find_csvs()
    print(f"  Found {len(csvs)} CSV file(s):\n")

    results: list = []
    total_seen = 0

    for csv_path in sorted(csvs):
        total_seen = process_csv(csv_path, model, scaler, label_map,
                                 results, total_seen)

    if not results:
        print("\n  WARNING: No attack flows met the confidence threshold.")
        print("  Check that your CSVs contain CIC-IDS-2017 attack traffic.\n")
        sys.exit(1)

    # ── Summarise by class ─────────────────────────────────────────────────
    from collections import Counter
    class_counts = Counter(r["_label"] for r in results)
    print()
    print(f"  ✔  Total verified attack flows: {len(results):,}")
    print()
    for cls, cnt in sorted(class_counts.items()):
        avg_conf = np.mean([r["_conf"] for r in results if r["_label"] == cls])
        print(f"    {cls:22s}: {cnt:4d} flows  (avg confidence: {avg_conf:.1%})")

    # ── Save ───────────────────────────────────────────────────────────────
    with open(OUT_FILE, "w", encoding="utf-8") as fh:
        json.dump(results, fh)

    print()
    print(f"  Saved → {OUT_FILE}")
    print()
    print("  You can now run:  python simulate_attacks.py")
    print()
