import streamlit as st
import validators
import socket
import requests
import whois
import ssl
import datetime
from urllib.parse import urlparse, parse_qs, unquote

st.set_page_config(page_title="URL Security Scanner", layout="wide")

st.title("🔍 URL Security Scanner")
st.write("Enter any URL to scan for security, DNS, SSL, and structural information.")

url = st.text_input("Enter URL", placeholder="https://example.com")


# ---------------------------
# Helper Functions
# ---------------------------

def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "Unable to resolve"


def get_dns(domain):
    try:
        result = socket.gethostbyname_ex(domain)
        return result
    except:
        return None


def get_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5.0)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return cert
    except:
        return None


def expand_url(url):
    try:
        r = requests.get(url, timeout=5)
        return r.url
    except:
        return url


# ---------------------------
# Main Scan
# ---------------------------

if url:
    st.subheader("📌 Scan Results")

    if not validators.url(url):
        st.error("❌ Invalid URL format")
    else:
        parsed = urlparse(url)

        # Expanded URL
        expanded = expand_url(url)

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### 🌐 URL Structure")
            st.write(f"*Original URL:* {url}")
            st.write(f"*Expanded URL:* {expanded}")
            st.write(f"*Protocol:* {parsed.scheme}")
            st.write(f"*Domain:* {parsed.netloc}")
            st.write(f"*Path:* {parsed.path if parsed.path else 'None'}")
            st.write(f"*Port:* {parsed.port if parsed.port else 'Default'}")

            params = parse_qs(parsed.query)
            st.write("*Query Parameters:*")
            st.json(params if params else "No parameters")

            st.write("*Decoded URL:*")
            st.code(unquote(url))

        # WHOIS, DNS, SSL
        with col2:
            domain = parsed.hostname

            st.markdown("### 🛡 Domain & Security Info")

            # IP
            ip = get_ip(domain)
            st.write(f"*IP Address:* {ip}")

            # DNS
            dns = get_dns(domain)
            st.write("*DNS Records:*")
            st.json(dns if dns else "Unable to fetch")

            # WHOIS
            try:
                whois_info = whois.whois(domain)
                st.write("*WHOIS Info:*")
                st.json({
                    "Registrar": whois_info.registrar,
                    "Creation Date": str(whois_info.creation_date),
                    "Expiry Date": str(whois_info.expiration_date),
                    "Country": whois_info.country
                })
            except:
                st.warning("WHOIS lookup failed.")

            # SSL Certificate
            ssl_info = get_ssl_info(domain)
            st.write("*SSL Certificate:*")
            st.json(ssl_info if ssl_info else "No SSL / Failed to fetch")

        # Simple Threat Checks
        st.subheader("🚨 Threat Indicators")

        threats = []

        if parsed.scheme != "https":
            threats.append("❗ URL is not using HTTPS")

        suspicious_tlds = ["xyz", "top", "tk", "ml"]
        if parsed.hostname.split(".")[-1] in suspicious_tlds:
            threats.append("⚠ Suspicious TLD detected")

        if "-" in parsed.hostname:
            threats.append("⚠ Domain contains hyphens (possible phishing)")

        if len(parsed.hostname) > 25:
            threats.append("⚠ Very long domain name")

        st.write(threats if threats else "✅ No basic threat indicators found")


st.info("✔ This tool checks URL structure, DNS, SSL, WHOIS, parameters, and phishing indicators.")
