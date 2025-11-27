import streamlit as st
import validators
import requests
from urllib.parse import urlparse, parse_qs, unquote
import datetime

# ---------------------------
# PAGE SETTINGS
# ---------------------------
st.set_page_config(page_title="CyberScanX - URL Scanner", layout="wide")


# ---------------------------
# CUSTOM CSS (Clean Modern Theme)
# ---------------------------
st.markdown("""
<style>

body { background:#ffffff; }

* {
    font-family: 'Segoe UI', sans-serif;
}

.title {
    font-size: 34px;
    font-weight: 700;
    color:#111;
}

.subtitle {
    font-size:14px;
    color:#6a6a6a;
    margin-bottom:25px;
}

.input-label {
    font-size:14px !important;
    color:#333 !important;
    font-weight:500;
}

.stTextInput input {
    background:#f7f7f7 !important;
    border:1px solid #dcdcdc !important;
    border-radius:8px !important;
    font-size: 15px !important;
    padding:10px !important;
}

.stTextInput input:focus {
    border:1.5px solid #4a72ff !important;
    box-shadow:0 0 10px rgba(74,114,255,0.15) !important;
}

.scan-title {
    font-size:22px;
    font-weight:600;
    margin-top:20px;
    color:#222;
}

.section-header {
    margin-top:15px;
    font-size:18px;
    font-weight:600;
    color:#333;
}

.code-box {
    background:#f4f4f4;
    border:1px solid #ddd;
    border-radius:6px;
    padding:10px;
    font-family:'Courier New', monospace;
    font-size:14px;
}

.risk-box {
    padding:12px;
    border-radius:6px;
    font-weight:600;
    font-size:16px;
    border:1px solid #bbb;
    background:#fafafa;
}

.low { border-left:6px solid #2ecc71; }
.medium { border-left:6px solid #f4c542; }
.high { border-left:6px solid #e74c3c; }

.risk-note {font-size:13px; color:#555; margin-top:4px;}

.threat {
   padding:8px;
   border-left:4px solid #f4c542;
   background:#fff6d9;
   border-radius:4px;
   margin-bottom:6px;
   font-size:14px;
}

.success {
   padding:10px;
   border-left:4px solid #2ecc71;
   background:#e9fbe9;
   border-radius:4px;
   font-size:14px;
}

footer {visibility:hidden;}

</style>
""", unsafe_allow_html=True)


# ---------------------------
# HEADER
# ---------------------------
st.markdown('<div class="title">🛡 CyberScanX</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">Analyze URLs for structure and basic phishing risks.</div>', unsafe_allow_html=True)

# ---------------------------
# INPUT
# ---------------------------
url = st.text_input("🔗 Enter URL", placeholder="https://example.com")


# ---------------------------
# FUNCTIONS
# ---------------------------
def expand_url(url: str) -> str:
    try:
        r = requests.get(url, timeout=5)
        return r.url
    except:
        return url

def risk_level(count):
    if count == 0:
        return "Low", "low", "No obvious threat indicators detected."
    elif count <= 2:
        return "Medium", "medium", "Some suspicious characteristics — proceed carefully."
    else:
        return "High", "high", "Multiple red flags. This link may be unsafe."


# ---------------------------
# SCAN LOGIC
# ---------------------------

if url:
    st.markdown('<div class="scan-title">Scan Results</div>', unsafe_allow_html=True)

    if not validators.url(url):
        st.error("❌ Invalid URL. Use a valid format like: https://example.com")
    else:
        parsed = urlparse(url)
        expanded = expand_url(url)
        params = parse_qs(parsed.query)

        threats = []

        if parsed.scheme != "https":
            threats.append("⚠ Not using HTTPS (insecure connection).")
        if "-" in (parsed.hostname or ""):
            threats.append("⚠ Domain contains hyphens (often used in phishing).")
        if len(parsed.hostname or "") > 25:
            threats.append("⚠ Domain name unusually long.")
        if len(params) > 5:
            threats.append("⚠ Excessive query parameters (tracking or malicious behavior possible).")

        suspicious_tlds = ["xyz", "tk", "ml", "top"]
        if parsed.hostname and parsed.hostname.split(".")[-1] in suspicious_tlds:
            threats.append("⚠ Suspicious top-level domain.")

        risk, level_class, note = risk_level(len(threats))

        # Structure block
        st.markdown('<div class="section-header">URL Overview</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="code-box">{url}</div>', unsafe_allow_html=True)

        if expanded != url:
            st.write("Redirects to:")
            st.markdown(f'<div class="code-box">{expanded}</div>', unsafe_allow_html=True)

        # Info
        st.markdown('<div class="section-header">Structure Breakdown</div>', unsafe_allow_html=True)
        st.write(f"📌 **Protocol:** `{parsed.scheme}`")
        st.write(f"📌 **Domain:** `{parsed.netloc}`")
        st.write(f"📌 **Path:** `{parsed.path if parsed.path else '/'}`")
        st.write(f"📌 **Parameters:** `{params if params else 'None'}`")

        # Risk Card
        st.markdown('<div class="section-header">Risk Level</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="risk-box {level_class}">{risk}</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="risk-note">{note}</div>', unsafe_allow_html=True)

        # Threats
        st.markdown('<div class="section-header">Threat Indicators</div>', unsafe_allow_html=True)

        if threats:
            for t in threats:
                st.markdown(f'<div class="threat">{t}</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="success">✔ Clean — No suspicious patterns detected.</div>', unsafe_allow_html=True)

# FOOTER
st.markdown("<br><center style='font-size:12px; color:#888;'>CyberScanX — Lightweight URL Security Preview Tool</center>", unsafe_allow_html=True)
