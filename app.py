# Compact, Streamlit-ready CyberscanX app (working version)
# Save this as app.py in your Streamlit project.
# This version is robust: it safely loads a logo (local repo file or uploaded /mnt/data path),
# avoids crashing if the image is missing, and uses a compact professional layout that
# works both locally and on Streamlit Cloud.

import streamlit as st
from PIL import Image
import time
import os

st.set_page_config(page_title="CyberscanX — Compact", layout="centered")

# -----------------------
# Helper: safe image loader
# -----------------------
# We include these candidates so the app works in multiple environments:
# 1) logo.png (recommended: place this file in the same repo as app.py)
# 2) your uploaded local file path (dev only): /mnt/data/08af1f3f-86aa-4b6a-a3d4-89f5b9a41ee4.png
# If none exist, we'll show a text fallback (so the app never crashes).
logo_candidates = [
    "logo.png",  # put a logo.png next to app.py (recommended for Streamlit Cloud)
    "/mnt/data/08af1f3f-86aa-4b6a-a3d4-89f5b9a41ee4.png",  # dev/uploaded file path
]

logo_path = None
for p in logo_candidates:
    if os.path.exists(p):
        logo_path = p
        break

# -----------------------
# Compact CSS (subtle) - safe and small
# -----------------------
st.markdown(
    """
    <style>
    :root{--page-bg:#f5f7fb}
    html,body,#root, .block-container{background:var(--page-bg);}
    .block-container{max-width:880px;padding-top:12px;padding-bottom:8px;padding-left:18px;padding-right:18px}
    header {visibility: hidden}
    .card{background:#ffffff;border-radius:10px;padding:14px;margin-bottom:12px;box-shadow:0 6px 18px rgba(15,20,30,0.06)}
    .muted{color:#6b7280;font-size:13px}
    .row{display:flex;gap:12px}
    .col{flex:1}
    .footer{font-size:12px;color:#8b94a6}
    </style>
    """,
    unsafe_allow_html=True,
)

# -----------------------
# Header: simple light-color title (no logo)
# -----------------------
st.markdown('<div class="card" style="background:#fafcff">', unsafe_allow_html=True)
st.markdown('<div style="font-size:22px;font-weight:700">CyberscanX — SQL Injection Scanner</div>', unsafe_allow_html=True)
st.markdown('<div class="muted">Educational demo — use only on legal targets (DVWA, JuiceShop, WebGoat)</div>', unsafe_allow_html=True)
st.markdown('</div>', unsafe_allow_html=True)

# -----------------------
with st.container():
    st.markdown('<div class="card" style="display:flex;align-items:center;gap:14px">', unsafe_allow_html=True)
    cols = st.columns([1,6])
    with cols[0]:
        if logo_path:
            try:
                img = Image.open(logo_path)
                st.image(img, width=64)
            except Exception:
                st.markdown('<div style="font-size:22px;font-weight:700">CyberscanX — SQL Injection Scanner</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div style="font-size:22px;font-weight:700">CyberscanX — SQL Injection Scanner</div>', unsafe_allow_html=True)
    with cols[1]:
        st.markdown('<div style="font-size:20px;font-weight:700">CyberscanX — SQL Injection Scanner</div>', unsafe_allow_html=True)
        st.markdown('<div class="muted">Educational demo — use only on legal targets (DVWA, JuiceShop, WebGoat)</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

# -----------------------
# Compact input card
# -----------------------
with st.container():
    st.markdown('<div class="card">', unsafe_allow_html=True)
    with st.form('scan_form'):
        st.markdown('**Target URL (DVWA / JuiceShop demo only)**')
        target = st.text_input('', value='http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit')

        c1, c2 = st.columns(2)
        with c1:
            timeout = st.number_input('Timeout (seconds)', min_value=1, value=8, step=1)
        with c2:
            delay = st.number_input('Delay between requests (seconds)', min_value=0.0, value=0.2, step=0.05, format='%.2f')

        st.markdown('<div class="muted">This is a basic educational scanner. Do NOT scan public websites.</div>', unsafe_allow_html=True)

        run = st.form_submit_button('Run Scan')
    st.markdown('</div>', unsafe_allow_html=True)

# -----------------------
# Results / progress card (won't show until Run)
# -----------------------
results_placeholder = st.empty()

if run:
    with results_placeholder.container():
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('**Scan progress**')
        prog = st.progress(0)
        stat = st.empty()

        # Simulate scanning steps (replace with your scanner logic)
        steps = 18
        found = []
        for i in range(steps + 1):
            frac = i / steps
            prog.progress(frac)
            stat.markdown(f'<div class="muted">Scanning payload {i} / {steps} — checking response...</div>', unsafe_allow_html=True)
            # simulate variable wait but respect the user delay
            time.sleep(max(0.02, float(delay)))

            # demo detection logic (fake) — replace with real checks
            if i in (5, 11, 16):
                found.append({'type': 'Possible SQLi', 'payload': f"' OR '1'='1' -- {i}", 'evidence': 'server responded with SQL error'})

        if found:
            st.markdown('<div style="margin-top:10px;font-weight:600">Vulnerabilities found</div>', unsafe_allow_html=True)
            for v in found:
                st.markdown(f"- **{v['type']}** — `{v['payload']}` — <span class='muted'>{v['evidence']}</span>", unsafe_allow_html=True)
        else:
            st.markdown('<div style="margin-top:10px;font-weight:600">No obvious vulnerabilities detected</div>', unsafe_allow_html=True)

        st.markdown('<div class="footer" style="margin-top:10px">Tip: Increase timeout for slow demo servers. Export feature coming soon.</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

# -----------------------
# Bottom quick controls (non-intrusive)
# -----------------------
st.divider()
col1, col2, col3 = st.columns([1,1,2])
with col1:
    st.button('Payloads')
with col2:
    st.button('Settings')
with col3:
    st.markdown('<div class="muted" style="text-align:right">Designed for educational demos • Do not misuse</div>', unsafe_allow_html=True)

# End of file
