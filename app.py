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
# CUSTOM CSS (Hacking Green Theme)
# ---------------------------
st.markdown("""
<style>
body {
    background-color: #000000;
}
* {
    font-family: 'Consolas', monospace;
}
.title {
    color: #00ff41;
    font-size: 36px;
    font-weight: bold;
    margin-bottom: -8px;
}
.subtitle {
    color:#00ff41aa;
    font-size: 14px;
    margin-bottom:20px;
}

.input-box {
    background: #000;
    border: 1px solid #00ff41;
    border-radius: 8px;
    padding: 12px;
}

.stTextInput > label {color:#00ff41 !important;}

.stTextInput input {
    background: #000;
    color:#00ff41 !important;
    border:1px solid #00ff41 !important;
    border-radius:10px;
}

.scan-title {
    margin-top: 20px;
    font-size: 22px;
    color:#00ff41;
    font-weight:bold;
}

.section-header {
    font-size:18px;
    margin-top:15px;
    margin-bottom:5px;
    color:#00ff41;
}

.code-box {
    background: black;
    border: 1px solid #00ff41;
    padding: 10px;
    border-radius: 6px;
    color:#00ff41;
    font-family:'Consolas';
}

.risk-box {
    padding: 15px;
    border-radius: 6px;
    border: 1px solid #00ff41;
    background: black;
    margin-top: 5px;
}

.check-ok {
    color: #03fc88;
    font-size: 14px;
}

.check-warn {
    color: #ffea00;
    font-size: 14px;
}

.check-danger {
    color: #ff0033;
    font-size: 14px;
}

footer {
    visibility: hidden;
}
</style>
""", unsafe_allow_html=True)


# ---------------------------
# HEADER
# ---------------------------
st.markdown('<div class="title">🛡 CyberScanX</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">Analyze URLs for structural risks & phishing patterns.</div>', unsafe_allow_html=True)

# ---------------------------
# INPUT
# ---------------------------
url = st.text_input("🔗 Enter URL", placeholder="https://example.com")


# ---------------------------
# HELPER FUNCTIONS
# ---------------------------
def expand_url(url: str) -> str:
    try:
        r = requests.get(url, timeout=5)
        return r.url
    except:
        return url

def get_risk_level(count):
    if count == 0:
        return "LOW", "check-ok"
    elif count <=2:
        return "MEDIUM", "check-warn"
    else:
        return "HIGH", "check-danger"


# ---------------------------
# MAIN SCAN
# ---------------------------
if url:
    st.markdown('<div class="scan-title">SCAN RESULTS</div>', unsafe_allow_html=True)

    if not validators.url(url):
        st.error("❌ Invalid URL. Use full format like https://example.com")
    else:
        parsed = urlparse(url)
        expanded = expand_url(url)

        threats = []

        if parsed.scheme != "https":
            threats.append("⚠ Not using HTTPS")

        suspicious_tlds = ["xyz","tk","ml","top"]
        if parsed.hostname and parsed.hostname.split(".")[-1] in suspicious_tlds:
            threats.append("⚠ Suspicious TLD detected")

        if "-" in (parsed.hostname or ""):
            threats.append("⚠ Hyphens found (common in fake domains)")

        if len(parsed.hostname or "") > 25:
            threats.append("⚠ Domain is unusually long")

        if len(parse_qs(parsed.query)) > 5:
            threats.append("⚠ Too many query parameters")

        risk, risk_style = get_risk_level(len(threats))

        # Overview
        st.markdown('<div class="section-header">URL Overview</div>', unsafe_allow_html=True)
        st.markdown(f"<div class='code-box'>{url}</div>", unsafe_allow_html=True)

        if expanded != url:
            st.write("Redirects to:")
            st.markdown(f"<div class='code-box'>{expanded}</div>", unsafe_allow_html=True)

        # Structure
        st.markdown('<div class="section-header">Structure</div>', unsafe_allow_html=True)
        st.write(f"🔹 Protocol: `{parsed.scheme}`")
        st.write(f"🔹 Domain: `{parsed.netloc}`")
        st.write(f"🔹 Path: `{parsed.path or '/'}`")
        st.write(f"🔹 Parameters: `{parse_qs(parsed.query) or 'None'}`")

        # Risk
        st.markdown('<div class="section-header">Risk Level</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="risk-box {risk_style}">Risk: {risk}</div>', unsafe_allow_html=True)

        # Threats
        st.markdown('<div class="section-header">Threat Indicators</div>', unsafe_allow_html=True)
        
        if threats:
            for t in threats:
                st.markdown(f"<div class='check-warn'>{t}</div>", unsafe_allow_html=True)
        else:
            st.markdown("<div class='check-ok'>✔ No threat indicators detected.</div>", unsafe_allow_html=True)

# ---------------------------
# FOOTER
# ---------------------------
st.markdown("<br><center style='color:#00ff41aa'>CyberScanX ⚡ No logs. No tracking.</center>", unsafe_allow_html=True)
