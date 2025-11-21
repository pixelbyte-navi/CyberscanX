# app.py - CyberscanX (fixed URL builder; live checks, no demo simulation)
# Real (lightweight) SQL Injection checks for educational/demo targets only.
# WARNING: Only scan systems you own or have explicit permission to test.

import streamlit as st
import pandas as pd
import requests
import time
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import json
import re
import os

st.set_page_config(page_title="CyberscanX — Live Scanner", layout="centered")

# -----------------------
# Small CSS for professional look
# -----------------------
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
    .tiny{font-size:12px;color:#9aa3b2}
    pre {background:#f4f6f8;padding:10px;border-radius:6px}
    </style>
    """,
    unsafe_allow_html=True,
)

# -----------------------
# Helper functions
# -----------------------
SQL_ERROR_PATTERNS = [
    r"SQL syntax", r"mysql", r"you have an error in your sql", r"syntax error",
    r"unclosed quotation mark", r"ORA-", r"PostgreSQL", r"pg_query\(", r"SQLite3::",
    r"sqlstate", r"Warning: \S*mysqli", r"mysql_fetch", r"SQLSTATE"
]
SQL_ERROR_RE = re.compile("|".join(SQL_ERROR_PATTERNS), re.IGNORECASE)

def find_query_params(url):
    """Return dict of query params and their values (parse_qs), and parsed parts."""
    parts = urlparse(url)
    return parse_qs(parts.query), parts

def build_url_with_param(parts, params, key, new_value):
    """
    Return new URL with modified single parameter value (keeps other params).
    Handles params values that may be lists or strings safely.
    """
    # Normalize params into a simple dict of single values
    normalized = {}
    for k, v in params.items():
        if isinstance(v, list):
            normalized[k] = v[0] if len(v) > 0 else ""
        else:
            # If v is a string or other type, keep it
            normalized[k] = v

    # Set the new value for the target key
    normalized[key] = new_value

    # urlencode expects a mapping of strings
    new_query = urlencode(normalized, doseq=False)
    new_parts = parts._replace(query=new_query)
    return urlunparse(new_parts)

def detect_error_based(resp_text):
    """Return True if response contains SQL error patterns."""
    if resp_text is None:
        return False
    return bool(SQL_ERROR_RE.search(resp_text))

def safe_request_get(url, timeout):
    """Perform GET request with exceptions handled. Return (status_code, text, elapsed_seconds)."""
    try:
        t0 = time.time()
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        elapsed = time.time() - t0
        return r.status_code, r.text, elapsed
    except requests.exceptions.RequestException as e:
        return None, str(e), None

def findings_to_df(findings):
    if not findings:
        return pd.DataFrame(columns=['id','timestamp','severity','type','param','payload','evidence','notes'])
    df = pd.DataFrame(findings)
    cols = ['id','timestamp','severity','type','param','payload','evidence','notes']
    for c in cols:
        if c not in df.columns:
            df[c] = ''
    return df[cols]

def severity_badge_html(s):
    s_low = s.lower()
    if s_low == 'high':
        return '<span class="badge high">HIGH</span>'
    if s_low == 'medium':
        return '<span class="badge medium">MEDIUM</span>'
    if s_low == 'low':
        return '<span class="badge low">LOW</span>'
    return '<span class="badge">INFO</span>'

# -----------------------
# Payloads (lightweight and mostly non-destructive)
# - error-based patterns
# - boolean-based (simple)
# - time-based (light sleep)
# -----------------------
PAYLOADS = [
    {"payload":"'", "type":"error"},
    {"payload":"' OR '1'='1", "type":"boolean"},
    {"payload":"' OR '1'='1' -- ", "type":"boolean"},
    {"payload":"' OR 1=1 -- ", "type":"boolean"},
    {"payload":"' UNION SELECT NULL-- ", "type":"union"},
    # time-based - keep short (2s) to avoid long waits
    {"payload":"' OR SLEEP(2) -- ", "type":"time", "sleep":2},
    {"payload":"' OR IF(1=1,SLEEP(2),0) -- ", "type":"time", "sleep":2},
]

# -----------------------
# UI: Header + Input
# -----------------------
st.markdown('<div class="card">', unsafe_allow_html=True)
st.markdown('<div style="font-size:22px;font-weight:800">CyberscanX — SQL Injection Scanner (Live)</div>', unsafe_allow_html=True)
st.markdown('<div class="muted">Run lightweight checks on legal demo targets only. The tool will perform simple probes and gather potential indicators.</div>', unsafe_allow_html=True)
st.markdown('</div>', unsafe_allow_html=True)

with st.form('scan_form'):
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('**Target URL (must include query parameters)**')
    target = st.text_input('', value='http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit')
    c1, c2 = st.columns(2)
    with c1:
        timeout = st.number_input('Timeout (seconds)', min_value=1, value=8, step=1)
    with c2:
        delay = st.number_input('Delay between requests (seconds)', min_value=0.0, value=0.3, step=0.05, format='%.2f')
    st.markdown('<div class="muted">Only run against local/demo targets you control. Scanning public sites without permission is illegal.</div>', unsafe_allow_html=True)
    run = st.form_submit_button('Run Scan')
    st.markdown('</div>', unsafe_allow_html=True)

results_area = st.empty()

# -----------------------
# Main scanning flow (no demo simulation)
# -----------------------
if run:
    # Basic validation
    if not target or '?' not in target:
        st.warning("Please provide a target URL that includes query parameters (e.g., ?id=1&name=x).")
    else:
        # Parse params
        params, parts = find_query_params(target)
        if not params:
            st.warning("No query parameters found in the URL. Scanner needs at least one parameter to test.")
        else:
            with results_area.container():
                st.markdown('<div class="card">', unsafe_allow_html=True)
                st.markdown('**Scan status**')
                prog = st.progress(0)
                status = st.empty()

                # baseline: request with original target to measure baseline length and time
                status.markdown('<div class="tiny">Taking baseline request for comparison...</div>', unsafe_allow_html=True)
                code, text, elapsed = safe_request_get(target, timeout)
                baseline_len = len(text) if text else 0
                baseline_time = elapsed if elapsed else 0.0
                time.sleep(0.12)

                findings = []
                total_checks = len(params) * len(PAYLOADS)
                i = 0
                for param_key in params.keys():
                    # original value to replace
                    orig_v = params[param_key]
                    # determine a safe original string
                    orig_val = orig_v[0] if isinstance(orig_v, list) and len(orig_v) > 0 else (str(orig_v) if orig_v is not None else "")
                    for p in PAYLOADS:
                        i += 1
                        fraction = i / max(1, total_checks)
                        prog.progress(fraction)
                        status.markdown(f'<div class="tiny">{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")} — Testing param <strong>{param_key}</strong> with payload <code>{p["payload"]}</code></div>', unsafe_allow_html=True)
                        # build test URL
                        test_url = build_url_with_param(parts, params, param_key, orig_val + p["payload"])
                        code_t, text_t, elapsed_t = safe_request_get(test_url, timeout)

                        # small delay to be polite
                        time.sleep(max(0.02, float(delay)))

                        evidence = ""
                        severity = None
                        finding_type = None

                        # Check time-based triggers if payload type is 'time'
                        if p.get("type") == "time":
                            if elapsed_t and baseline_time is not None:
                                sleep_time = p.get("sleep", 2)
                                if elapsed_t and (elapsed_t - baseline_time) > (sleep_time * 0.6):
                                    severity = "High"
                                    finding_type = "Time-based SQLi (possible)"
                                    evidence = f"Response time increased: baseline={baseline_time:.2f}s, test={elapsed_t:.2f}s"
                        else:
                            # Check for SQL error messages in response
                            if text_t and detect_error_based(text_t):
                                severity = "Medium"
                                finding_type = "Error-based SQLi (possible)"
                                match = SQL_ERROR_RE.search(text_t)
                                snippet = match.group(0) if match else "SQL error pattern found"
                                evidence = f"Matched error pattern: {snippet}"
                            else:
                                # boolean-based heuristic: compare length differences or content differences
                                if p.get("type") == "boolean":
                                    false_payload = p["payload"] + " AND 1=2 -- "
                                    false_test_url = build_url_with_param(parts, params, param_key, orig_val + false_payload)
                                    _, false_text, _ = safe_request_get(false_test_url, timeout)
                                    len_diff = 0
                                    if false_text is not None and text_t is not None:
                                        len_diff = abs(len(false_text) - len(text_t))
                                    if len_diff > max(30, baseline_len * 0.02):  # 2% change or 30 chars
                                        severity = "Low"
                                        finding_type = "Boolean-based difference (possible)"
                                        evidence = f"Length difference detected between payload and control: diff={len_diff} chars"
                                    else:
                                        if text_t and false_text and text_t != false_text:
                                            severity = "Low"
                                            finding_type = "Boolean-based content difference (possible)"
                                            evidence = "Response bodies differ between payload and control (content mismatch)"
                        # if any finding detected, record it
                        if severity:
                            findings.append({
                                "id": len(findings) + 1,
                                "timestamp": datetime.utcnow().isoformat(),
                                "severity": severity,
                                "type": finding_type,
                                "param": param_key,
                                "payload": p["payload"],
                                "evidence": evidence,
                                "notes": "Please verify manually. Non-deterministic heuristics used."
                            })

                # present results
                df = findings_to_df(findings)
                high = (df['severity']=='High').sum() if not df.empty else 0
                medium = (df['severity']=='Medium').sum() if not df.empty else 0
                low = (df['severity']=='Low').sum() if not df.empty else 0

                st.markdown(f"<div style='display:flex;gap:12px;align-items:center;margin-top:8px'>"
                            f"<div style='font-weight:700'>Results summary</div>"
                            f"<div class='muted' style='margin-left:8px'>Total findings: <strong>{len(df)}</strong></div>"
                            f"<div style='margin-left:12px'>{severity_badge_html('High')} <span class='tiny' style='margin-left:6px'>{high}</span></div>"
                            f"<div style='margin-left:6px'>{severity_badge_html('Medium')} <span class='tiny' style='margin-left:6px'>{medium}</span></div>"
                            f"<div style='margin-left:6px'>{severity_badge_html('Low')} <span class='tiny' style='margin-left:6px'>{low}</span></div>"
                            f"</div>",
                            unsafe_allow_html=True)

                st.markdown('---')

                if not df.empty:
                    st.markdown('**Findings (click a row to copy details)**')
                    st.dataframe(df[['id','timestamp','severity','type','param','payload']], use_container_width=True)

                    for _, row in df.iterrows():
                        with st.expander(f"Finding #{int(row['id'])} — {row['severity']} — {row['type']}", expanded=False):
                            st.markdown(f"**Parameter:** `{row['param']}`")
                            st.markdown(f"**Payload:** `{row['payload']}`")
                            st.markdown("**Evidence:**")
                            st.code(row['evidence'])
                            st.markdown(f"**Notes:** {row['notes']}")
                            st.download_button(label='Download finding (JSON)',
                                               data=json.dumps(row.to_dict(), indent=2),
                                               file_name=f"finding_{int(row['id'])}.json",
                                               mime='application/json')
                    # Full report downloads
                    csv = df.to_csv(index=False).encode('utf-8')
                    json_report = df.to_json(orient='records', indent=2)
                    html_report = df.to_html(index=False)
                    st.download_button('Download full report (CSV)', data=csv, file_name='cyberscanx_report.csv', mime='text/csv')
                    st.download_button('Download full report (JSON)', data=json_report, file_name='cyberscanx_report.json', mime='application/json')
                    st.download_button('Download full report (HTML)', data=html_report, file_name='cyberscanx_report.html', mime='text/html')
                else:
                    st.markdown('<div style="font-weight:600;margin-top:8px">No obvious vulnerabilities detected by automated heuristics.</div>', unsafe_allow_html=True)

                st.markdown('</div>', unsafe_allow_html=True)

# If not run yet, show friendly instructions
if not run:
    with results_area.container():
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="muted">Enter a target URL (with query parameters), set a small delay and timeout, then click <strong>Run Scan</strong>. The scanner will perform lightweight, non-destructive checks and list any potential indicators of SQL injection. Always verify findings manually.</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

# Footer quick actions
st.divider()
col1, col2, col3 = st.columns([1,1,2])
with col1:
    st.button('Payloads')
with col2:
    st.button('Settings')
with col3:
    st.markdown('<div class="muted" style="text-align:right">Designed for educational demos • Do not misuse</div>', unsafe_allow_html=True)
