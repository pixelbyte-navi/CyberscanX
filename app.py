# CyberscanX — Professional Results Output (Streamlit)
# Save as app.py. This version focuses on professional, resume-ready output:
# - Clear metrics (vuln count, severity)
# - Results table + sortable dataframe
# - Expanders with details and example evidence
# - CSV / JSON / HTML download buttons
# - Clean, minimal style

import streamlit as st
import pandas as pd
import time
from datetime import datetime
import json
import os

st.set_page_config(page_title="CyberscanX — Professional", layout="centered")

# ---------- CSS ----------
st.markdown(
    """
    <style>
    :root{--page-bg:#f6f8fb}
    html,body,#root, .block-container{background:var(--page-bg);} 
    .block-container{max-width:920px;padding-top:14px;padding-bottom:14px}
    header {visibility:hidden}
    .card{background:#ffffff;border-radius:12px;padding:16px;margin-bottom:14px;box-shadow:0 8px 22px rgba(15,20,30,0.06)}
    .muted{color:#6b7280;font-size:13px}
    .badge{display:inline-block;padding:6px 10px;border-radius:999px;font-weight:600}
    .high{background:#ffe9e9;color:#9f1b1b}
    .medium{background:#fff4db;color:#8a5a00}
    .low{background:#e8f8ff;color:#03506f}
    .info{background:#eefaf1;color:#116529}
    .tiny{font-size:12px;color:#9aa3b2}
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------- Header ----------
st.markdown('<div class="card">', unsafe_allow_html=True)
st.markdown('<div style="font-size:22px;font-weight:800">CyberscanX — SQL Injection Scanner</div>', unsafe_allow_html=True)
st.markdown('<div class="muted">Professional results — use only on legal demo targets (DVWA, JuiceShop, WebGoat)</div>', unsafe_allow_html=True)
st.markdown('</div>', unsafe_allow_html=True)

# ---------- Input Card ----------
with st.form('scan_form'):
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('**Target URL (DVWA / JuiceShop demo only)**')
    target = st.text_input('', value='http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit')

    c1, c2 = st.columns(2)
    with c1:
        timeout = st.number_input('Timeout (seconds)', min_value=1, value=8, step=1)
    with c2:
        delay = st.number_input('Delay between requests (seconds)', min_value=0.0, value=0.2, step=0.05, format='%.2f')

    st.markdown('<div class="muted">This is an educational scanner. Do NOT scan public websites.</div>', unsafe_allow_html=True)
    run = st.form_submit_button('Run Scan')
    st.markdown('</div>', unsafe_allow_html=True)

# ---------- Placeholder for results ----------
results_area = st.empty()

# Helper: convert findings list to dataframe and JSON
def findings_to_df(findings):
    if not findings:
        return pd.DataFrame(columns=['id','timestamp','severity','type','payload','evidence','notes'])
    df = pd.DataFrame(findings)
    # ensure column order
    cols = ['id','timestamp','severity','type','payload','evidence','notes']
    for c in cols:
        if c not in df.columns:
            df[c] = ''
    return df[cols]

# Severity display helper
def severity_badge(s):
    s_low = s.lower()
    if s_low == 'high':
        return '<span class="badge high">HIGH</span>'
    if s_low == 'medium':
        return '<span class="badge medium">MEDIUM</span>'
    if s_low == 'low':
        return '<span class="badge low">LOW</span>'
    return '<span class="badge info">INFO</span>'

# ---------- Run scan (simulated) ----------
if run:
    # Simulate a scanning process and collect findings (replace with your logic)
    with results_area.container():
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('**Scan status**')
        progress = st.progress(0)
        status = st.empty()

        findings = []
        steps = 20
        for i in range(steps + 1):
            pct = i/steps
            progress.progress(pct)
            status.markdown(f'<div class="tiny">{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")} — Sending payload set {i}/{steps} …</div>', unsafe_allow_html=True)
            time.sleep(max(0.02, float(delay)))

            # Demo detection rules — replace with real checks
            if i in (5, 11, 16):
                severity = 'High' if i==5 else ('Medium' if i==11 else 'Low')
                findings.append({
                    'id': len(findings)+1,
                    'timestamp': datetime.utcnow().isoformat(),
                    'severity': severity,
                    'type': 'Possible SQL Injection',
                    'payload': f"' OR '1'='1' -- {i}",
                    'evidence': 'Server returned SQL error stack trace in response body',
                    'notes': 'Reproduce manually. Try boolean-based payloads and time-based tests.'
                })

        # Summary metrics
        df = findings_to_df(findings)
        high = (df['severity']=='High').sum() if not df.empty else 0
        medium = (df['severity']=='Medium').sum() if not df.empty else 0
        low = (df['severity']=='Low').sum() if not df.empty else 0

        st.markdown(f"<div style='display:flex;gap:12px;align-items:center;margin-top:8px'>"+
                    f"<div style='font-weight:700'>Results summary</div>"+
                    f"<div class='muted' style='margin-left:8px'>Total findings: <strong>{len(df)}</strong></div>"+
                    f"<div style='margin-left:12px'>{severity_badge('High')} <span class='tiny' style='margin-left:6px'>{high}</span></div>"+
                    f"<div style='margin-left:6px'>{severity_badge('Medium')} <span class='tiny' style='margin-left:6px'>{medium}</span></div>"+
                    f"<div style='margin-left:6px'>{severity_badge('Low')} <span class='tiny' style='margin-left:6px'>{low}</span></div>"+
                    "</div>", unsafe_allow_html=True)

        st.markdown('---')

        # If there are findings, show table and expanders
        if not df.empty:
            # Show a sortable dataframe
            st.markdown('**Findings (click a row to copy details)**')
            st.dataframe(df[['id','timestamp','severity','type','payload']], use_container_width=True)

            # Expanders with detailed view per finding
            for _, row in df.iterrows():
                with st.expander(f"Finding #{int(row['id'])} — {row['severity']} — {row['type']}", expanded=False):
                    st.markdown(f"**Payload:** `{row['payload']}`")
                    st.markdown(f"**Evidence:**")
                    st.code(row['evidence'])
                    st.markdown(f"**Notes:** {row['notes']}")
                    st.download_button(label='Download finding (JSON)', data=json.dumps(row.to_dict(), indent=2), file_name=f"finding_{int(row['id'])}.json", mime='application/json')

            # Download full report
            csv = df.to_csv(index=False).encode('utf-8')
            json_report = df.to_json(orient='records', indent=2)
            html_report = df.to_html(index=False)

            st.download_button('Download full report (CSV)', data=csv, file_name='cyberscanx_report.csv', mime='text/csv')
            st.download_button('Download full report (JSON)', data=json_report, file_name='cyberscanx_report.json', mime='application/json')
            st.download_button('Download full report (HTML)', data=html_report, file_name='cyberscanx_report.html', mime='text/html')

        else:
            st.markdown('<div style="font-weight:600;margin-top:8px">No obvious vulnerabilities detected</div>', unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)

# ---------- If nothing run yet, show friendly empty state ----------
if not run:
    with results_area.container():
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="muted">Press <strong>Run Scan</strong> to start the analysis. Results will appear here with structured details, severity levels, and downloadable reports.</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

# ---------- Footer quick actions ----------
st.divider()
col1, col2, col3 = st.columns([1,1,2])
with col1:
    st.button('Payloads')
with col2:
    st.button('Settings')
with col3:
    st.markdown('<div class="muted" style="text-align:right">Designed for educational demos • Do not misuse</div>', unsafe_allow_html=True)

# End of file
