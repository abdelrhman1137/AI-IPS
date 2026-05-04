import ast, os, json, random

print("=== 1. Syntax check ===")
for f in ['dashboard_ids.py','network_receptor.py','simulate_attacks.py']:
    with open(f, encoding='utf-8') as fh:
        src = fh.read()
    try:
        ast.parse(src)
        print("  OK  " + f)
    except SyntaxError as e:
        print("  FAIL " + f + ": " + str(e))

print()
print("=== 2. flush_all() test ===")
from network_receptor import NetworkReceptor
r = NetworkReceptor()

for i in range(50):
    r._queue.put({"test": i})

line = '{"Destination Port":80}\n'
with open(r.INJECT_FILE, 'w') as fh:
    fh.write(line * 20)

before = r._queue.qsize()
print(f"  Queue before: {before}")

discarded = r.flush_all()
after = r._queue.qsize()
print(f"  flush_all() returned: {discarded}")
print(f"  Queue after: {after}")

file_content = open(r.INJECT_FILE).read().strip()
print(f"  Inject file cleared: {file_content == ''}")
os.remove(r.INJECT_FILE)

print()
print("=== 3. Self-test prediction check ===")
import joblib, numpy as np

model     = joblib.load('trained_ids_model.pkl')
scaler    = joblib.load('scaler.pkl')
label_map = joblib.load('label_map.pkl')

FEAT_COLS = [
    'Destination Port','Flow Duration','Total Fwd Packets',
    'Total Length of Fwd Packets','Fwd Packet Length Max',
    'Fwd Packet Length Min','Fwd Packet Length Mean','Fwd Packet Length Std',
    'Flow Bytes/s','Flow Packets/s','Average Packet Size',
]

with open('verified_attacks.json') as f:
    data = json.load(f)

sample = random.sample(data, 12)
alerts = 0
for row in sample:
    vals   = [row[k] for k in FEAT_COLS]
    scaled = scaler.transform([vals])
    probs  = model.predict_proba(scaled)[0]
    idx    = int(np.argmax(probs))
    conf   = float(probs[idx])
    lbl    = label_map.get(idx, 'Unknown')
    if conf >= 0.80 and lbl != 'Normal Traffic':
        alerts += 1

print(f"  12 test flows -> {alerts} alerts (expect 9-12)")
print("  Result: " + ("PASS" if alerts >= 8 else "WARN — fewer detections than expected"))

print()
print("All checks complete.")
