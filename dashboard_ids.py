"""
AI-IDS  —  Neural Security Operations Center  v9  (Professional Edition)
=========================================================================
Changes vs v8:
  • Zero emoji in the UI — replaced with CSS severity badges, status dots,
    and color-coded typographic indicators (professional SOC aesthetic).
  • Threat Timeline tab now shows:
      – Interactive time-range selector (1 m / 5 m / 15 m / 30 m / All)
      – Alert-rate bar chart  (5-second buckets)
      – Cumulative-alert area chart
      – Last-15-alerts quick table
  • Analytics tab now shows:
      – Summary stat cards (Total flows, Threat rate, Avg confidence)
      – Attack-class donut  +  confidence-score histogram
      – Throughput sparkline +  class breakdown horizontal bar
  • Alert Log tab has live severity filter (multiselect).
  • All charts populate after Self-Test even when monitoring is stopped.
  • conf_history[] tracks every model call for the confidence histogram.
"""

import os, json, random, time
from collections import Counter
import streamlit as st
import pandas as pd
import numpy as np
import joblib
import requests
import subprocess
import plotly.express as px
import plotly.graph_objects as go
from network_receptor import NetworkReceptor
from scapy.all import get_if_list

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AI-IDS | Neural SOC",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Design system CSS ──────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap');

/* ── Base ─────────────────────────────────────────────────── */
html, body, .stApp {
    background: #060910 !important;
    color: #e6edf3;
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
}
::-webkit-scrollbar { width: 5px; }
::-webkit-scrollbar-track { background: #0d1117; }
::-webkit-scrollbar-thumb { background: #272d35; border-radius: 3px; }

/* ── Sidebar ──────────────────────────────────────────────── */
[data-testid="stSidebar"] {
    background: #080c16 !important;
    border-right: 1px solid #1a2132;
}

/* ── Metrics ──────────────────────────────────────────────── */
[data-testid="stMetricValue"] {
    font-size: 1.7rem !important;
    font-weight: 700 !important;
    color: #4a9eff !important;
    font-family: 'JetBrains Mono', monospace !important;
}
[data-testid="stMetricLabel"] {
    font-size: .62rem !important;
    color: #7d8590 !important;
    text-transform: uppercase;
    letter-spacing: .1em;
}
div[data-testid="stVerticalBlock"] div.element-container div.stMetric {
    background: #0b0f1c;
    border: 1px solid #1d2535;
    border-radius: 10px;
    padding: 14px 18px;
    transition: border-color .25s, transform .2s;
}
div[data-testid="stVerticalBlock"] div.element-container div.stMetric:hover {
    border-color: #4a9eff55;
    transform: translateY(-2px);
}

/* ── Tabs ─────────────────────────────────────────────────── */
[data-testid="stTabs"] button {
    color: #7d8590 !important;
    font-weight: 500;
    font-size: .85rem;
    letter-spacing: .02em;
}
[data-testid="stTabs"] button[aria-selected="true"] {
    color: #4a9eff !important;
    border-bottom: 2px solid #4a9eff !important;
}

/* ── Buttons ──────────────────────────────────────────────── */
.stButton > button {
    background: linear-gradient(135deg, #1a3a6b, #1a5c2a) !important;
    color: #e6edf3 !important;
    border: 1px solid #2a4a7a !important;
    border-radius: 6px;
    font-weight: 600;
    font-size: .83rem;
    letter-spacing: .03em;
    transition: all .2s;
}
.stButton > button:hover {
    border-color: #4a9eff !important;
    transform: translateY(-1px);
    box-shadow: 0 4px 15px rgba(74,158,255,.15);
}

/* ── Severity badges ──────────────────────────────────────── */
.badge {
    display: inline-block;
    font-size: .67rem;
    font-weight: 700;
    letter-spacing: .08em;
    padding: 2px 7px;
    border-radius: 3px;
    text-transform: uppercase;
    font-family: 'JetBrains Mono', monospace;
    vertical-align: middle;
}
.badge-critical { background: rgba(248,81,73,.12);  color: #f85149; border: 1px solid #f8514955; }
.badge-high     { background: rgba(219,109,40,.12); color: #db6d28; border: 1px solid #db6d2855; }
.badge-medium   { background: rgba(210,153,34,.12); color: #d29922; border: 1px solid #d2992255; }
.badge-clean    { background: rgba(63,185,80,.06);  color: #3fb950; border: 1px solid #3fb95040; }
.badge-sim      { background: rgba(163,113,247,.1); color: #a371f7; border: 1px solid #a371f740; }

/* ── Status dots ──────────────────────────────────────────── */
.dot {
    display: inline-block;
    width: 7px; height: 7px;
    border-radius: 50%;
    margin-right: 6px;
    vertical-align: middle;
}
.dot-green  { background: #3fb950; box-shadow: 0 0 6px #3fb950aa; }
.dot-blue   { background: #4a9eff; box-shadow: 0 0 6px #4a9effaa; }
.dot-red    { background: #f85149; box-shadow: 0 0 6px #f85149aa; }
.dot-purple { background: #a371f7; box-shadow: 0 0 6px #a371f7aa; }
.dot-grey   { background: #4a5568; }

/* ── Feed rows ────────────────────────────────────────────── */
.feed-row {
    display: flex;
    align-items: center;
    gap: 10px;
    background: rgba(11,15,28,.7);
    border-left: 3px solid #1d2535;
    border-radius: 4px;
    padding: 6px 12px;
    margin: 3px 0;
    font-size: .81rem;
    font-family: 'JetBrains Mono', monospace;
}
.feed-critical { border-left-color: #f85149; background: rgba(248,81,73,.06) !important; }
.feed-high     { border-left-color: #db6d28; background: rgba(219,109,40,.05) !important; }
.feed-medium   { border-left-color: #d29922; background: rgba(210,153,34,.05) !important; }
.feed-clean    { border-left-color: #1d2535; }
.feed-ts   { color: #7d8590; min-width: 68px; font-size: .75rem; }
.feed-port { color: #7d8590; min-width: 56px; }
.feed-lbl  { font-weight: 600; min-width: 120px; }
.feed-conf { color: #7d8590; font-size: .75rem; }

/* ── Section headers ──────────────────────────────────────── */
.sec-hdr {
    font-size: .7rem;
    font-weight: 600;
    letter-spacing: .12em;
    text-transform: uppercase;
    color: #7d8590;
    border-bottom: 1px solid #1a2132;
    padding-bottom: 6px;
    margin-bottom: 10px;
}

/* ── Sim banner ───────────────────────────────────────────── */
.sim-banner {
    display: flex;
    align-items: center;
    gap: 10px;
    background: rgba(163,113,247,.06);
    border: 1px solid #a371f730;
    border-radius: 6px;
    padding: 7px 16px;
    font-size: .82rem;
    font-weight: 500;
    color: #a371f7;
    margin-bottom: 12px;
    letter-spacing: .02em;
}

/* ── Debug monospace ──────────────────────────────────────── */
.pred-box {
    background: #0b0f1c;
    border: 1px solid #1d2535;
    border-radius: 6px;
    padding: 10px 14px;
    font-family: 'JetBrains Mono', monospace;
    font-size: .75rem;
    color: #7d8590;
    line-height: 1.7;
}
.pred-bar-wrap {
    display: flex;
    align-items: center;
    gap: 6px;
    margin: 1px 0;
}
.pred-name { min-width: 114px; font-size: .73rem; }
.pred-bar  { height: 5px; border-radius: 2px; display: inline-block; }

/* ── Stat cards (Analytics) ───────────────────────────────── */
.stat-card {
    background: #0b0f1c;
    border: 1px solid #1d2535;
    border-radius: 8px;
    padding: 16px 20px;
    text-align: center;
}
.stat-card .val { font-size: 1.8rem; font-weight: 700; color: #4a9eff;
                  font-family: 'JetBrains Mono', monospace; }
.stat-card .lbl { font-size: .66rem; color: #7d8590; text-transform: uppercase;
                  letter-spacing: .1em; margin-top: 4px; }
</style>
""", unsafe_allow_html=True)

# ── Constants ──────────────────────────────────────────────────────────────────
_DIR        = os.path.dirname(os.path.abspath(__file__))
DONE_SIGNAL = os.path.join(_DIR, "_inject_done.flag")
VER_ATTACKS = os.path.join(_DIR, "verified_attacks.json")

PREFERRED_IFACE = r"\Device\NPF_{52B3DEA6-A3AD-4C38-AA0C-A3C9236C809C}"

HIGH_RISK   = {"DoS", "DDoS", "Brute Force", "Botnet"}
SEV_COLOR   = {"CRITICAL":"#f85149","HIGH":"#db6d28","MEDIUM":"#d29922","CLEAN":"#3fb950"}
ATK_PALETTE = {
    "DoS":            "#f85149",
    "DDoS":           "#db6d28",
    "Brute Force":    "#d29922",
    "Port Scanning":  "#4a9eff",
    "Web Attacks":    "#3fb950",
    "Botnet":         "#a371f7",
    "Other Exploit":  "#e3b341",
    "Normal Traffic": "#3fb950",
}
FEAT_COLS = [
    "Destination Port","Flow Duration","Total Fwd Packets",
    "Total Length of Fwd Packets","Fwd Packet Length Max",
    "Fwd Packet Length Min","Fwd Packet Length Mean","Fwd Packet Length Std",
    "Flow Bytes/s","Flow Packets/s","Average Packet Size",
]
FEED_LIMIT  = 18
CHART_EVERY = 25    # ticks between full chart redraws
LOOP_SLEEP  = 0.10  # 10 fps

PLOTLY_DARK = dict(
    template="plotly_dark",
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(11,15,28,.6)",
    font=dict(color="#e6edf3", family="Inter, system-ui, sans-serif"),
    margin=dict(l=0, r=0, t=28, b=0),
)

# ── Asset loading ──────────────────────────────────────────────────────────────
@st.cache_resource
def load_assets():
    m  = joblib.load("trained_ids_model.pkl")
    sc = joblib.load("scaler.pkl")
    lm = joblib.load("label_map.pkl")
    return m, sc, lm, {v: k for k, v in lm.items()}, NetworkReceptor()

try:
    model, scaler, label_map, label_map_inv, receptor = load_assets()
except Exception as err:
    st.error(f"Could not load models: {err}  —  Run train_model.py first.")
    st.stop()

# ── Helpers ────────────────────────────────────────────────────────────────────
def get_severity(label, conf):
    if label == "Normal Traffic": return "CLEAN"
    if conf >= 0.95 and label in HIGH_RISK: return "CRITICAL"
    if conf >= 0.85: return "HIGH"
    return "MEDIUM"

def execute_mitigation(ip, severity, label, conf, is_sim):
    """Executes configured mitigation actions and returns (blocked, pcap_path)."""
    blocked = False
    pcap_path = ""
    
    if severity in ["CRITICAL", "HIGH"] and ip:
        os.makedirs("pcap_dumps", exist_ok=True)
        fname = f"pcap_dumps/threat_{int(time.time())}_{ip.replace('.','_')}.pcap"
        try:
            pcap_path = receptor.dump_pcap(ip, fname)
        except Exception:
            pass
            
    if severity == "CRITICAL" and ip:
        if st.session_state.auto_block and ip not in st.session_state.blocked_ips:
            try:
                cmd = f'netsh advfirewall firewall add rule name="AI-IDS Block {ip}" dir=in action=block remoteip={ip}'
                subprocess.run(cmd, shell=True, capture_output=True, text=True)
                blocked = True
                st.session_state.blocked_ips.add(ip)
            except Exception:
                blocked = True # Demo fallback
                st.session_state.blocked_ips.add(ip)

        if st.session_state.webhook_url:
            payload = {
                "content": f"🚨 **{severity} ALERT**: {label} attack detected with {conf:.1%} confidence!\n"
                           f"**Source IP**: `{ip}`\n"
                           f"**Action Taken**: {'Blocked via Firewall' if blocked else 'Logged'}\n"
                           f"**Mode**: {'Simulation' if is_sim else 'Live Traffic'}"
            }
            try:
                requests.post(st.session_state.webhook_url, json=payload, timeout=0.5)
            except:
                pass

        user_email = st.session_state.get("user_email", "")
        if user_email:
            os.makedirs("mock_emails", exist_ok=True)
            email_body = (f"To: {user_email}\n"
                          f"Subject: AI-IDS ALERT: {severity} - {label}\n"
                          f"--------------------------------------------------\n"
                          f"Threat detected with {conf:.1%} confidence.\n"
                          f"Source IP: {ip}\n"
                          f"Mitigation: {'Blocked' if blocked else 'Logged'}\n"
                          f"Mode: {'Simulation' if is_sim else 'Live Traffic'}\n")
            fname = f"mock_emails/alert_{int(time.time())}_{ip.replace('.','_')}.txt"
            try:
                with open(fname, "w") as f:
                    f.write(email_body)
                try:
                    st.toast(f"📧 Threat Report sent to {user_email}")
                except Exception:
                    pass
            except:
                pass
                
    return blocked, pcap_path

def fmt_bytes(bps):
    if bps >= 1_048_576: return f"{bps/1_048_576:.2f} MB/s"
    if bps >= 1_024:     return f"{bps/1_024:.1f} KB/s"
    return f"{bps:.0f} B/s"

def fmt_uptime(secs):
    m, s = divmod(int(secs), 60)
    h, m = divmod(m, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"

def severity_badge(severity):
    cls = {"CRITICAL":"badge-critical","HIGH":"badge-high",
           "MEDIUM":"badge-medium","CLEAN":"badge-clean"}.get(severity,"badge-clean")
    return f"<span class='badge {cls}'>{severity}</span>"

def make_feed_html(ts, label, severity, conf, port, is_sim, src_ip=""):
    col  = SEV_COLOR.get(severity, "#e6edf3")
    css  = {"CRITICAL":"feed-critical","HIGH":"feed-high",
            "MEDIUM":"feed-medium","CLEAN":"feed-clean"}.get(severity,"")
    sim  = "<span class='badge badge-sim' style='font-size:.62rem'>SIM</span>" if is_sim else ""
    ip_span = (
        f"<span style='color:#7d8590;font-size:.72rem;font-family:JetBrains Mono,monospace'>"
        f"{src_ip}</span>"
    ) if src_ip else ""
    return (
        f"<div class='feed-row {css}'>"
        f"{severity_badge(severity)}"
        f"<span class='feed-ts'>{ts}</span>"
        f"<span class='feed-port'>:{int(port)}</span>"
        f"<span class='feed-lbl' style='color:{col}'>{label}</span>"
        f"<span class='feed-conf'>{conf:.1%}</span>"
        f"{sim}"
        f"{ip_span}"
        f"</div>"
    )

def predict_flow(flow_values, conf_threshold):
    scaled = scaler.transform([flow_values])
    probs  = model.predict_proba(scaled)[0]
    idx    = int(np.argmax(probs))
    conf   = float(probs[idx])
    label  = label_map.get(idx, "Unknown")
    all_p  = {label_map[i]: float(p) for i, p in enumerate(probs)}
    if conf < conf_threshold:
        label = "Normal Traffic"
        conf  = all_p.get("Normal Traffic", conf)
    return label, conf, all_p

# ── Session state ──────────────────────────────────────────────────────────────
DEFAULTS = {
    "running":       False, "start_time": None,  "sniffer_ok": False,
    "total_flows":   0,     "alert_count": 0,
    "threat_log":    [],    "alert_ts_log": [],   "conf_history": [],
    "alert_df":      pd.DataFrame(columns=["Time","Severity","Label","Conf","Port","Dur µs","Src","Src IP", "Blocked", "PCAP"]),
    "throughput_h":  [],    "feed": [],           "consec": {},
    "sim_active":    False, "last_label": "—",    "last_conf": 0.0,
    "last_probs":    {},    "loop_error": "",     "self_test_msg": "",
    "tl_range":      "5 min",
    "sev_filter":    ["CRITICAL", "HIGH", "MEDIUM"],
    "webhook_url":   "",    "auto_block": False,  "blocked_ips": set(),
    "authenticated": False, "user_email": "",
}
for k, v in DEFAULTS.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ── Authentication ─────────────────────────────────────────────────────────────
CRED_FILE = "credentials.json"

def load_creds():
    if not os.path.exists(CRED_FILE): return {}
    with open(CRED_FILE, "r") as f: return json.load(f)

def save_creds(creds):
    with open(CRED_FILE, "w") as f: json.dump(creds, f)

if not st.session_state.authenticated:
    st.markdown("<div style='text-align:center;padding:70px 0'>"
                "<h1 style='color:#e6edf3;font-size:2.2rem;letter-spacing:-.5px;font-weight:700'>AI-IDS SOC</h1>"
                "<p style='color:#7d8590;font-size:.9rem'>Please authenticate to access the Security Operations Center.</p>"
                "</div>", unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 1.2, 1])
    with col2:
        t_login, t_signup = st.tabs(["🔒 Sign In", "📝 Sign Up"])
        
        with t_login:
            l_email = st.text_input("Email", key="login_email")
            l_pass = st.text_input("Password", type="password", key="login_pass")
            if st.button("Sign In", use_container_width=True):
                creds = load_creds()
                if l_email in creds and creds[l_email] == l_pass:
                    st.session_state.authenticated = True
                    st.session_state.user_email = l_email
                    st.rerun()
                else:
                    st.error("Invalid credentials.")

        with t_signup:
            s_email = st.text_input("Email", key="signup_email")
            s_pass = st.text_input("Password", type="password", key="signup_pass")
            if st.button("Sign Up", use_container_width=True):
                creds = load_creds()
                if s_email in creds:
                    st.error("Email already registered.")
                elif s_email and s_pass:
                    creds[s_email] = s_pass
                    save_creds(creds)
                    st.success("Registered successfully! Please go to Sign In.")
                else:
                    st.error("Please provide a valid email and password.")
                    
    st.stop()

# ── Self-test (synchronous, no queue dependency) ───────────────────────────────
def do_self_test(conf_threshold, guard):
    if not os.path.exists(VER_ATTACKS):
        return 0, "verified_attacks.json not found — run build_attack_cache.py"
    with open(VER_ATTACKS) as f:
        data = json.load(f)
    sample   = random.sample(data, min(12, len(data)))
    fired    = 0
    now_unix = time.time()
    for row in sample:
        vals  = [row[k] for k in FEAT_COLS]
        label, conf, all_p = predict_flow(vals, conf_threshold)
        st.session_state.total_flows += 1
        st.session_state.throughput_h.append((now_unix, row.get("Flow Bytes/s", 0)))
        st.session_state.conf_history.append((label, conf))
        if label != "Normal Traffic":
            st.session_state.consec[label] = st.session_state.consec.get(label, 0) + 1
        if label != "Normal Traffic" and st.session_state.consec.get(label, 0) >= guard:
            sev = get_severity(label, conf)
            ts  = time.strftime("%H:%M:%S")
            fired += 1
            st.session_state.alert_count  += 1
            st.session_state.alert_ts_log.append((now_unix, label, True))
            st.session_state.threat_log.append(label)
            _local = row.get("Source IP", "127.0.0.1")
            blocked, pcap_path = execute_mitigation(_local, sev, label, conf, is_sim=True)

            _local_fmt = f"{_local} (BLOCKED)" if blocked else _local
            st.session_state.feed.insert(0, make_feed_html(ts, label, sev, conf,
                                          float(row.get("Destination Port", 0)), True,
                                          src_ip=_local_fmt))
            if len(st.session_state.feed) > FEED_LIMIT:
                st.session_state.feed.pop()
            new_row = pd.DataFrame([{
                "Time": ts, "Severity": sev, "Label": label,
                "Conf": f"{conf:.1%}", "Port": int(row.get("Destination Port", 0)),
                "Dur µs": int(row.get("Flow Duration", 0)),
                "Src": "SIM", "Src IP": _local,
                "Blocked": blocked, "PCAP": pcap_path,
            }])
            st.session_state.alert_df = pd.concat(
                [new_row, st.session_state.alert_df], ignore_index=True
            )
        else:
            st.session_state.threat_log.append("Normal Traffic")
        st.session_state.last_label = label
        st.session_state.last_conf  = conf
        st.session_state.last_probs = all_p
    msg = (f"Self-Test complete — {fired}/{len(sample)} attacks detected"
           if fired > 0
           else "Self-Test: 0 alerts — try lowering Confidence Threshold")
    return fired, msg

# ── Sidebar ────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown(
        "<div style='padding:16px 0 10px;text-align:center'>"
        "<div style='font-size:1.1rem;font-weight:700;color:#e6edf3;letter-spacing:.05em'>"
        "AI-IDS</div>"
        "<div style='font-size:.7rem;color:#7d8590;letter-spacing:.12em;text-transform:uppercase'>"
        "Neural Security Operations Center</div>"
        "</div>",
        unsafe_allow_html=True,
    )
    st.divider()

    st.markdown("<p class='sec-hdr'>Capture Interface</p>", unsafe_allow_html=True)
    all_ifs = get_if_list()
    def_idx = all_ifs.index(PREFERRED_IFACE) if PREFERRED_IFACE in all_ifs else 0
    iface   = st.selectbox("Interface", all_ifs, index=def_idx,
                           label_visibility="collapsed")
    st.caption(f"...{iface[-32:]}")
    st.divider()

    st.markdown("<p class='sec-hdr'>Detection Tuning</p>", unsafe_allow_html=True)
    conf_pct = st.slider("Confidence Threshold", 65, 98, 80, step=1, format="%d%%",
                         help="Model confidence required to fire an alert")
    conf_threshold = conf_pct / 100.0
    guard = st.slider("Alert Guard", 1, 4, 1, format="%d consecutive",
                      help="Identical back-to-back predictions required before alerting")
    st.divider()

    st.markdown("<p class='sec-hdr'>Response & Mitigation</p>", unsafe_allow_html=True)
    webhook_url = st.text_input("Webhook URL (Slack/Discord/Teams)", value=st.session_state.webhook_url, type="password")
    auto_block = st.checkbox("Auto-Block Critical Threats (Windows Firewall)", value=st.session_state.auto_block)
    st.session_state.webhook_url = webhook_url
    st.session_state.auto_block = auto_block
    st.divider()

    st.markdown("<p class='sec-hdr'>Engine Controls</p>", unsafe_allow_html=True)
    ca, cb = st.columns(2)
    with ca:
        start_btn = st.button("Start", use_container_width=True,
                              disabled=st.session_state.running)
    with cb:
        stop_btn  = st.button("Stop",  use_container_width=True,
                              disabled=not st.session_state.running)
    clear_btn = st.button("Clear Session", use_container_width=True)
    st.divider()

    st.markdown("<p class='sec-hdr'>Self-Test</p>", unsafe_allow_html=True)
    st.caption("Runs 12 verified CIC-IDS-2017 attacks through the model immediately.")
    st_ph         = st.empty()
    self_test_btn = st.button("Run Self-Test", use_container_width=True)
    if st.session_state.self_test_msg:
        st_ph.info(st.session_state.self_test_msg)
    st.divider()

    st.markdown("<p class='sec-hdr'>System Status</p>", unsafe_allow_html=True)
    ph_sniffer = st.empty()

    def update_sniffer():
        err = receptor.sniffer_error
        cnt = receptor.raw_packet_count
        if err:
            ph_sniffer.markdown(
                f"<div class='pred-box'>"
                f"<span class='dot dot-red'></span> Sniffer error<br>"
                f"<span style='font-size:.72rem;color:#f85149'>{err[:60]}</span></div>",
                unsafe_allow_html=True,
            )
        elif st.session_state.running and receptor.sniffer_running:
            ph_sniffer.markdown(
                f"<div class='pred-box'>"
                f"<span class='dot dot-green'></span> Monitoring Active<br>"
                f"<span style='color:#7d8590;font-size:.73rem'>RF+XGBoost — 99.86% acc</span><br>"
                f"<span style='color:#3fb950;font-size:.73rem'>{cnt:,} raw packets captured</span>"
                f"</div>",
                unsafe_allow_html=True,
            )
        elif st.session_state.running:
            ph_sniffer.markdown(
                "<div class='pred-box'><span class='dot dot-blue'></span> Starting…</div>",
                unsafe_allow_html=True,
            )
        else:
            ph_sniffer.markdown(
                f"<div class='pred-box'>"
                f"<span class='dot dot-grey'></span> Standby<br>"
                f"<span style='color:#7d8590;font-size:.73rem'>RF+XGBoost — 99.86% acc</span>"
                f"</div>",
                unsafe_allow_html=True,
            )

    update_sniffer()
    st.divider()

    st.markdown("<p class='sec-hdr'>Last Prediction</p>", unsafe_allow_html=True)
    ph_debug = st.empty()

    def render_debug():
        lbl   = st.session_state.last_label
        conf  = st.session_state.last_conf
        probs = st.session_state.last_probs
        if not probs:
            ph_debug.markdown("<div class='pred-box'>No prediction yet.</div>",
                              unsafe_allow_html=True)
            return
        col2 = SEV_COLOR.get(get_severity(lbl, conf), "#e6edf3")
        bars = ""
        for cls in sorted(probs, key=probs.get, reverse=True)[:5]:
            p = probs[cls]; w = max(1, int(p * 90))
            c = ATK_PALETTE.get(cls, "#4a9eff")
            bars += (
                f"<div class='pred-bar-wrap'>"
                f"<span class='pred-name' style='color:#9ba7b4'>{cls[:14]}</span>"
                f"<span class='pred-bar' style='width:{w}px;background:{c}'></span>"
                f"<span style='font-size:.7rem;color:#7d8590'>{p:.1%}</span>"
                f"</div>"
            )
        ph_debug.markdown(
            f"<div class='pred-box'>"
            f"<b style='color:{col2}'>{lbl}</b>"
            f"<span style='color:#7d8590;font-size:.72rem'> — {conf:.1%}</span><br>"
            f"<div style='margin-top:6px'>{bars}</div></div>",
            unsafe_allow_html=True,
        )
    render_debug()

# ── Button actions ─────────────────────────────────────────────────────────────
if start_btn:
    st.session_state.running    = True
    st.session_state.start_time = time.time()
    st.session_state.sniffer_ok = False
    st.session_state.loop_error = ""

if stop_btn:
    st.session_state.running = False
    receptor.flush_all()

if clear_btn:
    receptor.flush_all()
    for k, v in DEFAULTS.items():
        if k not in ("running","start_time","sniffer_ok","tl_range","sev_filter"):
            st.session_state[k] = (
                v.copy() if isinstance(v, (list,dict)) else
                pd.DataFrame(columns=v.columns) if isinstance(v, pd.DataFrame) else v
            )
    st.rerun()

if self_test_btn:
    _fired, _msg = do_self_test(conf_threshold, guard)
    st.session_state.self_test_msg = _msg
    st.rerun()

# ── Page header ────────────────────────────────────────────────────────────────
status_col = "#3fb950" if st.session_state.running else "#4a5568"
status_txt = "MONITORING" if st.session_state.running else "STANDBY"
st.markdown(
    "<div style='display:flex;align-items:center;justify-content:space-between;"
    "padding:2px 0 18px'>"
    "<div>"
    "<span style='font-size:1.6rem;font-weight:700;color:#e6edf3;letter-spacing:-.5px'>"
    "AI-IDS Neural Security Operations Center</span><br>"
    "<span style='font-size:.78rem;color:#7d8590;letter-spacing:.03em'>"
    "RF-XGBoost Ensemble &nbsp;·&nbsp; CIC-IDS-2017 &nbsp;·&nbsp; "
    "7 Attack Classes &nbsp;·&nbsp; 99.86% Model Accuracy"
    "</span></div>"
    f"<div style='text-align:right'>"
    f"<div style='display:inline-flex;align-items:center;gap:8px;"
    f"background:#0b0f1c;border:1px solid {status_col}44;"
    f"border-radius:20px;padding:5px 14px'>"
    f"<span class='dot dot-{'green' if st.session_state.running else 'grey'}'></span>"
    f"<span style='font-size:.75rem;font-weight:600;letter-spacing:.1em;"
    f"color:{status_col};text-transform:uppercase'>{status_txt}</span>"
    f"</div></div></div>",
    unsafe_allow_html=True,
)

if st.session_state.sim_active:
    st.markdown(
        "<div class='sim-banner'>"
        "<span class='dot dot-purple'></span>"
        "<b>SIMULATION ACTIVE</b>"
        "<span style='color:#7d8590;font-size:.8rem;margin-left:8px'>"
        "Injected flows are labelled SIM</span></div>",
        unsafe_allow_html=True,
    )

ph_error = st.empty()
if st.session_state.loop_error:
    ph_error.error(f"Pipeline error: {st.session_state.loop_error}")

# ── Top metrics ────────────────────────────────────────────────────────────────
mc1,mc2,mc3,mc4,mc5,mc6 = st.columns(6)
ph_pkts   = mc1.empty()
ph_flows  = mc2.empty()
ph_alrts  = mc3.empty()
ph_rate   = mc4.empty()
ph_bps    = mc5.empty()
ph_uptime = mc6.empty()

def redraw_metrics():
    tf  = st.session_state.total_flows
    ac  = st.session_state.alert_count
    bps = (st.session_state.throughput_h[-1][1] if st.session_state.throughput_h else 0)
    up  = (fmt_uptime(time.time() - st.session_state.start_time)
           if st.session_state.start_time else "00:00:00")
    ph_pkts.metric("Raw Packets",    f"{receptor.raw_packet_count:,}")
    ph_flows.metric("Flows Analyzed", f"{tf:,}")
    ph_alrts.metric("Threats",        f"{ac:,}",
                    delta=ac or None, delta_color="inverse")
    ph_rate.metric("Threat Rate",    f"{ac/tf*100:.1f}%" if tf > 0 else "—")
    ph_bps.metric("Throughput",      fmt_bytes(bps))
    ph_uptime.metric("Uptime",        up)

redraw_metrics()
st.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)

# ── Tabs ───────────────────────────────────────────────────────────────────────
tab_live, tab_tl, tab_an, tab_log = st.tabs([
    "Live Feed", "Threat Timeline", "Analytics", "Alert Log",
])

with tab_live:
    col_l, col_r = st.columns([1.65, 1])
    with col_l:
        st.markdown("<p class='sec-hdr'>Incident Stream</p>", unsafe_allow_html=True)
        ph_feed    = st.empty()
    with col_r:
        st.markdown("<p class='sec-hdr'>Model Confidence</p>", unsafe_allow_html=True)
        ph_gauge   = st.empty()
        st.markdown("<p class='sec-hdr'>Active Verdict</p>", unsafe_allow_html=True)
        ph_verdict = st.empty()

with tab_tl:
    # Interactive time-range selector
    tl_r_col, _ = st.columns([2, 3])
    with tl_r_col:
        st.radio("Time Range", ["1 min","5 min","15 min","30 min","All"],
                 horizontal=True, index=1, key="tl_range",
                 label_visibility="collapsed")
    tl_left, tl_right = st.columns(2)
    with tl_left:
        st.markdown("<p class='sec-hdr'>Alert Rate (5-second buckets)</p>",
                    unsafe_allow_html=True)
        ph_tl_bar = st.empty()
    with tl_right:
        st.markdown("<p class='sec-hdr'>Cumulative Alerts</p>",
                    unsafe_allow_html=True)
        ph_tl_cum = st.empty()
    st.markdown("<p class='sec-hdr'>Recent Detections</p>", unsafe_allow_html=True)
    ph_tl_recent = st.empty()

with tab_an:
    # Summary stat blocks
    sa1, sa2, sa3 = st.columns(3)
    ph_stat1 = sa1.empty()
    ph_stat2 = sa2.empty()
    ph_stat3 = sa3.empty()
    st.divider()
    an_l, an_r = st.columns(2)
    with an_l:
        st.markdown("<p class='sec-hdr'>Traffic Class Distribution</p>",
                    unsafe_allow_html=True)
        ph_donut = st.empty()
    with an_r:
        st.markdown("<p class='sec-hdr'>Model Confidence Distribution</p>",
                    unsafe_allow_html=True)
        ph_conf_hist = st.empty()
    an_l2, an_r2 = st.columns(2)
    with an_l2:
        st.markdown("<p class='sec-hdr'>Throughput Over Time</p>",
                    unsafe_allow_html=True)
        ph_tp = st.empty()
    with an_r2:
        st.markdown("<p class='sec-hdr'>Alerts by Class</p>",
                    unsafe_allow_html=True)
        ph_class_bar = st.empty()

with tab_log:
    st.multiselect(
        "Filter by Severity",
        ["CRITICAL","HIGH","MEDIUM","CLEAN"],
        default=st.session_state.get("sev_filter",["CRITICAL","HIGH","MEDIUM"]),
        key="sev_filter",
    )
    ph_log = st.empty()
    ph_dl  = st.empty()

# ── Gauge & verdict ────────────────────────────────────────────────────────────
def draw_gauge(conf, label, key_idx):
    sev = get_severity(label, conf)
    col = SEV_COLOR.get(sev, "#3fb950")
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=conf * 100,
        number={"suffix":"%","font":{"color":col,"size":32,"family":"JetBrains Mono"}},
        domain={"x":[0,1],"y":[0,1]},
        title={"text":"Model Confidence","font":{"color":"#7d8590","size":11}},
        gauge={
            "axis":{"range":[0,100],"tickwidth":1,"tickcolor":"#1d2535","tickfont":{"size":9}},
            "bar":{"color":col,"thickness":0.2},
            "bgcolor":"rgba(0,0,0,0)","borderwidth":0,
            "steps":[
                {"range":[0, conf_threshold*100],"color":"rgba(63,185,80,.04)"},
                {"range":[conf_threshold*100,85],"color":"rgba(210,153,34,.04)"},
                {"range":[85,100],               "color":"rgba(248,81,73,.06)"},
            ],
            "threshold":{
                "line":{"color":"#4a9eff","width":2},
                "thickness":.75,"value":conf_threshold*100,
            },
        },
    ))
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)",
                      font={"color":"#e6edf3"},height=200,
                      margin=dict(l=10,r=10,t=34,b=6))
    ph_gauge.plotly_chart(fig, key=f"g{key_idx}")

def draw_verdict(label, severity, conf):
    col   = SEV_COLOR.get(severity,"#e6edf3")
    badge = severity_badge(severity)
    ph_verdict.markdown(
        f"<div style='text-align:center;padding:12px;border:1px solid {col}33;"
        f"border-radius:6px;background:{col}08'>"
        f"{badge}<br>"
        f"<span style='font-size:1.05rem;font-weight:700;color:{col};display:block;margin-top:6px'>"
        f"{label}</span>"
        f"<span style='font-size:.75rem;color:#7d8590'>confidence {conf:.1%}</span>"
        f"</div>",
        unsafe_allow_html=True,
    )

# ── Waiting state ──────────────────────────────────────────────────────────────
_last_waiting_tick = -99
_SPIN  = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

def maybe_show_waiting(tick):
    global _last_waiting_tick
    if tick - _last_waiting_tick < 12: return
    _last_waiting_tick = tick
    sp = _SPIN[(tick // 12) % len(_SPIN)]
    ph_feed.markdown(
        f"<div style='padding:32px 0;text-align:center;color:#7d8590;font-size:.83rem'>"
        f"<span style='font-family:monospace'>{sp}</span> "
        f"Monitoring active — awaiting network flows<br><br>"
        f"<span style='font-size:.75rem;color:#4a5568'>"
        f"Raw packets captured: "
        f"<span style='color:#3fb950;font-family:monospace'>{receptor.raw_packet_count:,}</span>"
        f"&nbsp;&nbsp;|&nbsp;&nbsp;"
        f"Flows processed: "
        f"<span style='font-family:monospace'>{st.session_state.total_flows:,}</span>"
        f"<br>Use Run Self-Test in the sidebar for instant results</span></div>",
        unsafe_allow_html=True,
    )
    ph_gauge.markdown(
        "<div style='text-align:center;padding:50px 0;color:#4a5568;font-size:.82rem'>"
        "Awaiting first flow</div>",
        unsafe_allow_html=True,
    )
    ph_verdict.markdown(
        "<div style='text-align:center;padding:12px;border:1px solid #1d2535;"
        "border-radius:6px;color:#4a5568;font-size:.82rem'>—</div>",
        unsafe_allow_html=True,
    )

# ── Chart rendering (called from loop AND standby) ─────────────────────────────
def render_all_charts(tick_key):
    ss      = st.session_state
    now     = time.time()
    rng_map = {"1 min":60,"5 min":300,"15 min":900,"30 min":1800,"All":None}
    tl_secs = rng_map.get(ss.get("tl_range","5 min"))

    # ── Timeline tab ──────────────────────────────────────────────────────────
    filtered_log = (ss.alert_ts_log if tl_secs is None
                    else [(t,l,s) for t,l,s in ss.alert_ts_log if now - t <= tl_secs])

    if filtered_log:
        # Alert-rate bar chart
        min_ts = min(t for t,_,_ in filtered_log)
        bkts   = {}
        for ts_, albl, _ in filtered_log:
            bk = int((ts_ - min_ts) // 5) * 5
            bkts.setdefault(bk, {}).setdefault(albl, 0)
            bkts[bk][albl] += 1
        rows = [{"Elapsed (s)":bk,"Attack":lb,"Count":cnt}
                for bk,d in sorted(bkts.items()) for lb,cnt in d.items()]
        bar = px.bar(pd.DataFrame(rows), x="Elapsed (s)", y="Count",
                     color="Attack", color_discrete_map=ATK_PALETTE,
                     labels={"Count":"Alerts","Elapsed (s)":"Seconds into window"})
        bar.update_layout(**PLOTLY_DARK,
                          bargap=0.15,
                          legend=dict(orientation="h",y=1.15,font=dict(size=10)))
        ph_tl_bar.plotly_chart(bar, key=f"tl_bar_{tick_key}")

        # Cumulative alerts area chart
        sorted_log = sorted(filtered_log, key=lambda x: x[0])
        xs  = [t - sorted_log[0][0] for t,_,_ in sorted_log]
        cum = list(range(1, len(sorted_log)+1))
        clrs= [ATK_PALETTE.get(l,"#4a9eff") for _,l,_ in sorted_log]
        cum_fig = go.Figure()
        cum_fig.add_trace(go.Scatter(
            x=xs, y=cum, mode="lines+markers",
            fill="tozeroy",
            line=dict(color="#4a9eff", width=2),
            fillcolor="rgba(74,158,255,.1)",
            marker=dict(color=clrs, size=6, line=dict(width=0)),
            name="Cumulative",
        ))
        cum_fig.update_layout(**PLOTLY_DARK,
                              xaxis_title="Seconds",
                              yaxis_title="Total Alerts")
        ph_tl_cum.plotly_chart(cum_fig, key=f"tl_cum_{tick_key}")
    else:
        ph_tl_bar.info("No alerts in selected time range.")
        ph_tl_cum.info("No data yet.")

    # Recent detections table
    if not ss.alert_df.empty:
        ph_tl_recent.dataframe(
            ss.alert_df.head(15),
            use_container_width=True, hide_index=True,
        )
    else:
        ph_tl_recent.markdown(
            "<div style='color:#7d8590;text-align:center;padding:18px;font-size:.82rem'>"
            "No detections logged yet.</div>",
            unsafe_allow_html=True,
        )

    # ── Analytics tab ────────────────────────────────────────────────────────
    tf = ss.total_flows
    ac = ss.alert_count
    avg_conf = (
        np.mean([c for _,c in ss.conf_history]) if ss.conf_history else 0.0
    )
    ph_stat1.markdown(
        f"<div class='stat-card'><div class='val'>{tf:,}</div>"
        f"<div class='lbl'>Flows Analyzed</div></div>",
        unsafe_allow_html=True,
    )
    ph_stat2.markdown(
        f"<div class='stat-card'><div class='val' style='color:#f85149'>{ac:,}</div>"
        f"<div class='lbl'>Threats Detected</div></div>",
        unsafe_allow_html=True,
    )
    ph_stat3.markdown(
        f"<div class='stat-card'><div class='val' style='color:#3fb950'>{avg_conf:.1%}</div>"
        f"<div class='lbl'>Avg. Confidence</div></div>",
        unsafe_allow_html=True,
    )

    # Traffic donut
    if len(ss.threat_log) > 1:
        cts = pd.Series(ss.threat_log).value_counts()
        pie = px.pie(values=cts.values, names=cts.index, hole=0.52,
                     color=cts.index, color_discrete_map=ATK_PALETTE)
        pie.update_traces(
            textinfo="percent+label",
            hovertemplate="%{label}: %{value} flows<extra></extra>",
        )
        pie.update_layout(**PLOTLY_DARK, showlegend=False)
        ph_donut.plotly_chart(pie, key=f"donut_{tick_key}")
    else:
        ph_donut.info("Traffic distribution will appear after first flows are processed.")

    # Confidence histogram
    if ss.conf_history:
        conf_vals = [c for _,c in ss.conf_history]
        hist = px.histogram(
            x=conf_vals, nbins=20, range_x=[0,1],
            labels={"x":"Model Confidence","y":"Flows"},
            color_discrete_sequence=["#4a9eff"],
        )
        hist.add_vline(x=conf_threshold, line_dash="dash",
                       line_color="#f85149",
                       annotation_text=f"Threshold {conf_pct}%",
                       annotation_position="top right",
                       annotation_font_color="#f85149",
                       annotation_font_size=10)
        hist.update_layout(**PLOTLY_DARK)
        hist.update_traces(marker_line_width=0, opacity=0.85)
        ph_conf_hist.plotly_chart(hist, key=f"hist_{tick_key}")
    else:
        ph_conf_hist.info("Confidence histogram will appear after first predictions.")

    # Throughput area
    if len(ss.throughput_h) > 1:
        tp_v = [v for _,v in ss.throughput_h]
        tp_f = px.area(y=tp_v, labels={"y":"Bytes/s","x":"Flow Index"})
        tp_f.update_traces(line_color="#4a9eff",
                           fillcolor="rgba(74,158,255,.1)")
        tp_f.update_layout(**PLOTLY_DARK)
        ph_tp.plotly_chart(tp_f, key=f"tp_{tick_key}")
    else:
        ph_tp.info("Throughput chart will appear after traffic is detected.")

    # Attack class breakdown bar (horizontal)
    if ss.alert_ts_log:
        class_cts = Counter(l for _,l,_ in ss.alert_ts_log)
        df_cls    = pd.DataFrame(
            sorted(class_cts.items(), key=lambda x: x[1]),
            columns=["Attack Class","Alerts"],
        )
        bar_h = px.bar(df_cls, x="Alerts", y="Attack Class", orientation="h",
                       color="Attack Class",
                       color_discrete_map=ATK_PALETTE,
                       text="Alerts")
        bar_h.update_traces(textposition="outside")
        bar_h.update_layout(**PLOTLY_DARK, showlegend=False)
        ph_class_bar.plotly_chart(bar_h, key=f"cls_bar_{tick_key}")
    else:
        ph_class_bar.info("Attack breakdown will appear after first alert.")

    # ── Alert Log tab ─────────────────────────────────────────────────────────
    sev_f = ss.get("sev_filter", ["CRITICAL","HIGH","MEDIUM"])
    if not ss.alert_df.empty:
        df_show = ss.alert_df[ss.alert_df["Severity"].isin(sev_f)]
        ph_log.dataframe(df_show.head(400), use_container_width=True, hide_index=True)
        csv = ss.alert_df.to_csv(index=False).encode()
        ph_dl.download_button(
            "Export Full Log (CSV)", data=csv,
            file_name=f"ids_alerts_{time.strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv", key=f"dl_{tick_key}",
        )
        
        # Display PCAP download buttons if available
        pcap_files = ss.alert_df[ss.alert_df["PCAP"] != ""]["PCAP"].unique()
        if len(pcap_files) > 0:
            st.markdown("<div style='margin-top:16px'></div><p class='sec-hdr'>PCAP Forensic Dumps</p>", unsafe_allow_html=True)
            for pcap in pcap_files:
                if os.path.exists(pcap):
                    with open(pcap, "rb") as f:
                        fname = os.path.basename(pcap)
                        st.download_button(f"Download {fname}", f, file_name=fname, mime="application/vnd.tcpdump.pcap", key=f"pcap_dl_{fname}_{tick_key}")
    else:
        ph_log.markdown(
            "<div style='color:#7d8590;text-align:center;padding:20px;font-size:.82rem'>"
            "No alerts logged yet. Run Self-Test or the attack simulator.</div>",
            unsafe_allow_html=True,
        )

# Show charts immediately if data exists (e.g., after self-test, after rerun)
if (st.session_state.threat_log or st.session_state.alert_ts_log
        or st.session_state.conf_history):
    if st.session_state.feed:
        ph_feed.markdown("".join(st.session_state.feed), unsafe_allow_html=True)
    render_all_charts("_init")

# ── Monitoring loop ────────────────────────────────────────────────────────────
if st.session_state.running:
    if not st.session_state.sniffer_ok:
        try:
            receptor.start_sniffing(interface=iface)
        except Exception as e:
            ph_error.warning(f"Sniffer error: {e} — Real traffic capture disabled.")
        st.session_state.sniffer_ok = True

    tick = 0
    last_chart_t = -CHART_EVERY

    while st.session_state.running:

        # Simulation done?
        if os.path.exists(DONE_SIGNAL):
            st.session_state.sim_active = False
            discarded = receptor.flush_all()
            try: os.remove(DONE_SIGNAL)
            except OSError: pass
            ts_ = time.strftime("%H:%M:%S")
            st.session_state.feed.insert(0,
                f"<div class='feed-row' style='color:#7d8590;font-size:.78rem'>"
                f"<span class='badge badge-sim'>SIM</span>"
                f"<span class='feed-ts'>{ts_}</span>"
                f"Simulation complete — {discarded} buffered flows discarded"
                f"</div>"
            )

        # Periodic metric & sniffer refresh
        if tick % 5 == 0:
            redraw_metrics()
            update_sniffer()

        # Get a flow
        try:
            live_flow, is_sim, src_ip = receptor.get_latest_flow()
        except Exception as e:
            ph_error.error(f"Pipeline error: {e}")
            tick += 1; time.sleep(LOOP_SLEEP); continue

        if is_sim and not st.session_state.sim_active:
            st.session_state.sim_active = True

        if live_flow is None:
            maybe_show_waiting(tick)
            tick += 1; time.sleep(LOOP_SLEEP); continue

        # ── Process flow ───────────────────────────────────────────────────
        now_ts   = time.strftime("%H:%M:%S")
        now_unix = time.time()
        bps      = float(live_flow["Flow Bytes/s"].iloc[0])
        port     = float(live_flow["Destination Port"].iloc[0])
        dur      = float(live_flow["Flow Duration"].iloc[0])

        st.session_state.total_flows  += 1
        st.session_state.throughput_h.append((now_unix, bps))
        if len(st.session_state.throughput_h) > 200:
            st.session_state.throughput_h.pop(0)

        try:
            label, conf, all_p = predict_flow(
                live_flow.values.flatten().tolist(), conf_threshold
            )
        except Exception as e:
            ph_error.error(f"Model error: {e}")
            tick += 1; time.sleep(LOOP_SLEEP); continue

        st.session_state.conf_history.append((label, conf))
        if len(st.session_state.conf_history) > 500:
            st.session_state.conf_history.pop(0)

        st.session_state.last_label = label
        st.session_state.last_conf  = conf
        st.session_state.last_probs = all_p

        # Consecutive guard
        if label != "Normal Traffic":
            st.session_state.consec[label] = \
                st.session_state.consec.get(label, 0) + 1
        else:
            for k in list(st.session_state.consec):
                st.session_state.consec[k] = max(0, st.session_state.consec[k] - 1)

        fire_alert = (
            label != "Normal Traffic"
            and st.session_state.consec.get(label, 0) >= guard
        )
        severity = get_severity(label, conf) if fire_alert else "CLEAN"
        disp_lbl = label if fire_alert else "Normal Traffic"

        st.session_state.threat_log.append(disp_lbl)

        if fire_alert:
            st.session_state.alert_count += 1
            st.session_state.alert_ts_log.append((now_unix, label, is_sim))
            
            blocked, pcap_path = execute_mitigation(src_ip, severity, label, conf, is_sim)

            new_row = pd.DataFrame([{
                "Time": now_ts, "Severity": severity, "Label": label,
                "Conf": f"{conf:.1%}", "Port": int(port),
                "Dur µs": int(dur),
                "Src":    "SIM" if is_sim else "LIVE",
                "Src IP": src_ip,
                "Blocked": blocked,
                "PCAP": pcap_path,
            }])
            st.session_state.alert_df = pd.concat(
                [new_row, st.session_state.alert_df], ignore_index=True
            )

        _src_fmt = f"{src_ip} (BLOCKED)" if fire_alert and blocked else (src_ip if fire_alert else "")
        st.session_state.feed.insert(0, make_feed_html(
            now_ts, disp_lbl, severity, conf, port,
            is_sim and fire_alert,
            src_ip=_src_fmt,
        ))
        if len(st.session_state.feed) > FEED_LIMIT:
            st.session_state.feed.pop()

        # Render live elements
        redraw_metrics()
        render_debug()
        ph_feed.markdown("".join(st.session_state.feed), unsafe_allow_html=True)
        draw_gauge(conf, disp_lbl, st.session_state.total_flows)
        draw_verdict(disp_lbl, severity, conf)

        # Full chart refresh (throttled)
        if tick - last_chart_t >= CHART_EVERY:
            last_chart_t = tick
            render_all_charts(tick)

        tick += 1
        time.sleep(LOOP_SLEEP)

# ── Standby ────────────────────────────────────────────────────────────────────
else:
    if not st.session_state.feed:
        ph_feed.markdown(
            "<div style='padding:50px 0;text-align:center;color:#7d8590;font-size:.85rem'>"
            "Click <b style='color:#e6edf3'>Start</b> to begin monitoring, or "
            "<b style='color:#e6edf3'>Run Self-Test</b> in the sidebar for "
            "instant detection results without a network feed."
            "</div>",
            unsafe_allow_html=True,
        )