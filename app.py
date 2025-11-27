import streamlit as st
import validators
import requests
from urllib.parse import urlparse, parse_qs, unquote
import datetime

# ---------------------------
# Page Config
# ---------------------------
st.set_page_config(
    page_title="CyberScanX - URL Scanner",
    layout="wide",
)

# ---------------------------
# Custom Styles
# ---------------------------
st.markdown("""
    <style>
    .main-title {
        font-size: 32px;
        font-weight: 800;
        padding: 0;
        margin-bottom: 4px;
    }
    .subtitle {
        color: #888;
        font-size: 14px;
        margin-bottom: 20px;
    }
    .metric-card {
        padding: 14px 18px;
        border-radius: 12px;
        border: 1px solid #333333;
        background: #111111;
    }
    .risk-low {
        border-left: 5px solid #22c55e;
    }
    .risk-medium {
        border-left: 5px solid #eab308;
    }
    .risk-high {
        border-left: 5px solid #ef4444;
    }
    </style>
""", unsafe_allow_html=True)

# ---------------------------
# Header
# ---------------------------
st.markdown('<div class="main-title">🛡 CyberScanX – URL Scanner</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">Quickly inspect any URL for structure & basic phishing indicators.</div>', unsafe_allow_html=True)

# ---------------------------
# Input
# ---------------------------
with st.container():
    url = st.text_input("🔗 Enter URL", placeholder="https://example.com")

# ---------------------------
# Helper Functions
# ---------------------------
def expand_url(url: str) -> str:
    try:
        r = requests.get(url, timeout=5)
        return r.url
    except:
        return url


def get_risk_level(threat_count: int):
    if threat_count == 0:
        return "Low", "risk-low", "Looks safe based on basic checks."
    elif threat_count <= 2:
        return "Medium", "risk-medium", "Some suspicious signs detected. Review before trusting."
    else:
        return "High", "risk-high", "Multiple red flags. Be very careful with this URL."


# ---------------------------
# Main Scan
# ---------------------------
if url:
    st.markdown("---")
    st.subheader("📌 Scan Results")

    if not validators.url(url):
        st.error("❌ Invalid URL format. Please enter a full URL like `https://example.com`")
    else:
        scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        parsed = urlparse(url)
        expanded = expand_url(url)

        # ---------------------------
        # Threat Indicators
        # ---------------------------
        threats = []

        # 1. HTTPS check
        if parsed.scheme != "https":
            threats.append("❗ URL is not using HTTPS (connection may not be secure).")

        # 2. Suspicious TLDs
        suspicious_tlds = ["xyz", "top", "tk", "ml"]
        hostname = parsed.hostname or ""
        if hostname and hostname.split(".")[-1] in suspicious_tlds:
            threats.append("⚠ Suspicious TLD detected (commonly abused in phishing/scam sites).")

        # 3. Hyphens in domain
        if "-" in hostname:
            threats.append("⚠ Domain contains hyphens (sometimes used in fake / lookalike domains).")

        # 4. Lengthy domain
        if len(hostname) > 25:
            threats.append("⚠ Very long domain name (can be used to confuse users).")

        # 5. Query parameter count
        params = parse_qs(parsed.query)
        if len(params) > 5:
            threats.append("⚠ URL has many query parameters (may be part of tracking / malicious links).")

        # Risk level
        risk_level, risk_class, risk_message = get_risk_level(len(threats))

        # ---------------------------
        # Layout: Overview + Risk
        # ---------------------------
        col1, col2 = st.columns([1.6, 1])

        with col1:
            st.markdown("### 🌐 URL Overview")

            st.markdown("**Original URL:**")
            st.code(url, language="text")

            if expanded != url:
                st.markdown("**Expanded / Final URL (after redirects):**")
                st.code(expanded, language="text")

            st.markdown("#### Basic Structure")
            st.write(f"**Protocol:** `{parsed.scheme or 'None'}`")
            st.write(f"**Domain / Host:** `{parsed.netloc or 'None'}`")
            st.write(f"**Path:** `{parsed.path or 'None'}`")
            st.write(f"**Port:** `{parsed.port if parsed.port else 'Default (based on protocol)'}`")

            st.markdown("#### Query Parameters")
            if params:
                st.json(params)
            else:
                st.write("No query parameters found.")

            st.markdown("#### Decoded URL")
            st.code(unquote(url), language="text")

        with col2:
            st.markdown("### 🔒 Risk Summary")
            st.markdown(
                f"""
                <div class="metric-card {risk_class}">
                    <h4 style="margin-bottom:6px;">Overall Risk Level</h4>
                    <p style="font-size:24px; font-weight:700; margin:0;">{risk_level}</p>
                    <p style="font-size:13px; color:#ccc; margin-top:6px;">{risk_message}</p>
                    <p style="font-size:12px; color:#777; margin-top:10px;">Scanned at: {scan_time}</p>
                </div>
                """,
                unsafe_allow_html=True
            )

            st.markdown("### 🚨 Threat Indicators")
            if threats:
                for t in threats:
                    st.markdown(f"- {t}")
            else:
                st.success("✅ No basic threat indicators found in this URL.")

# Footer info
st.markdown("---")
st.info("✔ CyberScanX checks URL structure & basic phishing indicators. This is a helper tool, not a full security engine.")
