# Compact, professional Streamlit UI for CyberscanX
# Save this as app.py (or replace your current app.py).
# It uses the uploaded logo image at the following local path:
# /mnt/data/08af1f3f-86aa-4b6a-a3d4-89f5b9a41ee4.png

import streamlit as st
import time

st.set_page_config(page_title="CyberscanX — Compact", layout="centered")

# ---- Custom CSS to reduce whitespace and make a compact, professional layout ----
st.markdown("""
<style>
:root{--card-bg:#ffffff;--page-bg:#f6f8fb}
html,body,#root, .block-container{background:var(--page-bg);}
.block-container{max-width:880px;padding-top:18px;padding-bottom:18px;padding-left:20px;padding-right:20px}
header {display:none} /* hide default streamlit header for compact look */
.stButton>button {padding: .45rem .9rem}
.stTextInput>div>div>input, .stNumberInput>div>input {height:38px}
.card {background:var(--card-bg);border-radius:12px;padding:18px;margin-bottom:12px;box-shadow:0 6px 18px rgba(15,20,30,0.06)}
.small-muted{color:#6b7280;font-size:13px}
.row{display:flex;gap:12px}
.col{flex:1}
.footer-note{font-size:12px;color:#8b94a6;margin-top:8px}
</style>
""", unsafe_allow_html=True)

# ---- Top card: logo + title ----
with st.container():
    st.markdown('<div class="card" style="display:flex;align-items:center;gap:14px">', unsafe_allow_html=True)
    cols = st.columns([1,6])
    with cols[0]:
        # <-- use uploaded file path as the logo
        st.image('/mnt/data/08af1f3f-86aa-4b6a-a3d4-89f5b9a41ee4.png', width=68)
    with cols[1]:
        st.markdown('<div style="font-size:22px;font-weight:700">CyberscanX — SQL Injection Scanner</div>', unsafe_allow_html=True)
        st.markdown('<div class="small-muted">Educational demo • Use only on legal demo targets (DVWA, JuiceShop, WebGoat)</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

# ---- Input card (compact) ----
with st.container():
    st.markdown('<div class="card">', unsafe_allow_html=True)
    with st.form(key='scan_form'):
        st.markdown('**Target (DVWA / JuiceShop demo only)**')
        url = st.text_input('', value='http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit')

        c1, c2 = st.columns([1,1])
        with c1:
            timeout = st.number_input('Timeout (s)', value=8, min_value=1, step=1, format='%d')
        with c2:
            delay = st.number_input('Delay between requests (s)', value=0.2, min_value=0.0, step=0.05, format='%.2f')

        st.markdown('<div class="small-muted">This is a basic educational scanner. Do NOT scan public websites.</div>', unsafe_allow_html=True)

        run = st.form_submit_button('Run Scan')
    st.markdown('</div>', unsafe_allow_html=True)

# ---- Results / progress area ----
result_card = st.empty()

if run:
    # compact progress & results
    with result_card.container():
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('**Scan progress**')
        progress = st.progress(0)
        status = st.empty()
        vulnerabilities = []

        # Example loop to simulate scan progress (replace with your scanning logic)
        steps = 20
        for i in range(steps+1):
            pct = i/steps
            progress.progress(pct)
            status.markdown(f'<div class="small-muted">Scanning payload set {i} / {steps} ...</div>', unsafe_allow_html=True)
            time.sleep(max(0.02, float(delay)))

            # fake detection rule (for demo) - replace with real detection
            if i in (6, 13):
                vulnerabilities.append({'payload':f"' OR '1'='1' -- {i}", 'type':'Possible SQLi', 'evidence':'response contains SQL error'})

        # final results
        if vulnerabilities:
            st.markdown('<div style="margin-top:10px;font-weight:600">Vulnerabilities found</div>', unsafe_allow_html=True)
            for v in vulnerabilities:
                st.markdown(f"- **{v['type']}** — `{v['payload']}` — <span class='small-muted'>{v['evidence']}</span>", unsafe_allow_html=True)
        else:
            st.markdown('<div style="margin-top:10px;font-weight:600">No obvious vulnerabilities detected</div>', unsafe_allow_html=True)

        st.markdown('<div class="footer-note">Tip: Increase timeout for slow demo servers. Export a report using the export button (coming soon).</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

# ---- Bottom compact controls: quick actions (non-intrusive) ----
st.divider()
c1,c2,c3 = st.columns([1,1,2])
with c1:
    st.button('Payloads')
with c2:
    st.button('Settings')
with c3:
    st.markdown('<div class="small-muted" style="text-align:right">Designed for educational demos • Do not misuse</div>', unsafe_allow_html=True)

# End of file
