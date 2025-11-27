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
        font-size: 34px;
        font-weight: 800;
        padding: 0;
        margin-bottom: 4px;
    }
    .subtitle {
        color: #777;
        font-size: 14px;
        margin-bottom: 0;
    }

    /* ---------- HERO HEADER AREA ---------- */
    .hero-wrapper {
        width: 100%;
        padding: 22px 26px;
        margin-top: 10px;
        margin-bottom: 18px;
        border-radius: 18px;
        background: linear-gradient(135deg, #f5f7ff, #eef3ff);
        border: 1px solid #e1e4ff;
        box-shadow: 0 14px 30px rgba(15, 23, 42, 0.06);
    }
    .hero-left-title {
        font-size: 26px;
        font-weight: 800;
        margin-bottom: 6px;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .hero-left-sub {
        font-size: 13px;
        color: #666;
        margin-bottom: 14px;
    }
    .hero-pill {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 4px 10px;
        border-radius: 999px;
        background: rgba(59, 130, 246, 0.09);
        font-size: 11px;
        color: #1d4ed8;
        margin-bottom: 10px;
    }

    .url-input-card {
        background: #ffffff;
        border-radius: 14px;
        padding: 10px 14px 4px 14px;
        border: 1px solid #dfe3f0;
        box-shadow: 0 8px 20px rgba(15, 23, 42, 0.05);
    }
    .url-input-label {
        font-size: 12px;
        font-weight: 600;
        color: #4b5563;
        margin-bottom: 4px;
    }

    /* style for the actual text input */
    .stTextInput > label {
        font-size: 0px !important;  /* hide default label */
        height: 0px !important;
    }
    .stTextInput input {
        border-radius: 10px !important;
        border: 1px solid #e5e7eb !important;
        padding: 10px 12px !important;
        font-size: 14px !important;
    }
    .stTextInput input:focus {
        border-color: #4f46e5 !important;
        box-shadow: 0 0 0 1px rgba(79, 70, 229, 0.4) !important;
    }

    /* Right side stats in hero */
    .hero-right-card {
        background: rgba(15, 23, 42, 0.96);
        border-radius: 16px;
        padding: 14px 16px;
        color: #f9fafb;
        border: 1px solid rgba(148, 163, 184, 0.5);
        font-size: 12px;
    }
    .hero-right-title {
        font-size: 13px;
        font-weight: 600;
        margin-bottom: 6px;
        display: flex;
        align-items: center;
        gap: 6px;
    }
    .hero-right-badge {
        font-size: 10px;
        padding: 3px 8px;
        border-radius: 999px;
        background: rgba(16, 185, 129,0.15);
        color: #6ee7b7;
    }
    .hero-right-list li {
        margin-bottom: 4px;
    }

    /* ---------- EXISTING RISK CARDS ---------- */
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
# HERO HEADER + INPUT
# ---------------------------
st.markdown("""
<div class="hero-wrapper">
""", unsafe_allow_html=True)

col_hero_left, col_hero_right = st.columns([1.8, 1])

with col_hero_left:
    st.markdown("""
        <div class="hero-pill">
            🛡 CyberScanX • URL Intelligence
        </div>
        <div class="hero-left-title">
            <span>CyberScanX – URL Scanner</span>
        </div>
        <div class="hero-left-sub">
            Quickly inspect any link for structural patterns & basic phishing indicators before you click.
        </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="url-input-card">', unsafe_allow_html=True)
    st.markdown('<div class="url-input-label">🔗 Enter URL to scan</div>', unsafe_allow_html=True)
    url = st.text_input(
        label="Enter URL",
        placeholder="https://example.com",
        label_visibility="collapsed"
    )
    st.markdown('</div>', unsafe_allow_html=True)

with col_hero_right:
    st.markdown("""
        <div class="hero-right-card">
            <div class="hero-right-title">
                ⚡ Live Checks
                <span class="hero-right-badge">Instant scan</span>
            </div>
            <ul class="hero-right-list">
                <li>Protocol & domain structure analysis</li>
                <li>Query parameter inspection</li>
                <li>Heuristic phishing indicators</li>
                <li>Simple Low / Medium / High risk score</li>
            </ul>
            <p style="margin-top:8px; font-size:11px; color:#9ca3af;">
                Paste any URL and hit enter. No data is stored.
            </p>
        </div>
    """, unsafe_allow_html=True)

st.markdown("</div>", unsafe_allow_html=True)  # close hero-wrapper

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

        # ---------- Threat Indicators ----------
        threats = []

        if parsed.scheme != "https":
            threats.append("❗ URL is not using HTTPS (connection may not be secure).")

        suspicious_tlds = ["xyz", "top", "tk", "ml"]
        hostname = parsed.hostname or ""
        if hostname and hostname.split(".")[-1] in suspicious_tlds:
            threats.append("⚠ Suspicious TLD detected (commonly abused in phishing/scam sites).")

        if "-" in hostname:
            threats.append("⚠ Domain contains hyphens (sometimes used in fake / lookalike domains).")

        if len(hostname) > 25:
            threats.append("⚠ Very long domain name (can be used to confuse users).")

        params = parse_qs(parsed.query)
        if len(params) > 5:
            threats.append("⚠ URL has many query parameters (may be part of tracking / malicious links).")

        risk_level, risk_class, risk_message = get_risk_level(len(threats))

        # ---------- Layout: Overview + Risk ----------
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

# Footer
st.markdown("---")
st.info("✔ CyberScanX checks URL structure & basic phishing indicators. This is a helper tool, not a full security engine.")
