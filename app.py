import streamlit as st
import requests
import urllib3
import socket
import ssl
import time
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup  # add beautifulsoup4 in requirements.txt

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

st.set_page_config(page_title="CyberscanX – Website Inspector", page_icon="🛡️", layout="wide")
DEFAULT_TIMEOUT = 20


# ================= STATUS MEANING =================
def get_status_meaning(code: int) -> str:
    meanings = {
        200: "OK – Request succeeded and the server returned the page correctly.",
        301: "Moved Permanently – The requested resource has been assigned a new URL.",
        302: "Found (Redirect) – Temporary redirect to another page.",
        400: "Bad Request – The request was invalid or malformed.",
        401: "Unauthorized – Login or authentication required.",
        403: "Forbidden – Access to this resource is denied.",
        404: "Not Found – The requested page or resource does not exist.",
        500: "Internal Server Error – Something went wrong on the server.",
        502: "Bad Gateway – Server received an invalid response from another server.",
        503: "Service Unavailable – Server is overloaded or blocking automated traffic.",
        504: "Gateway Timeout – Server took too long to respond.",
    }
    return meanings.get(code, "Unknown status code or no description available.")


# ================= NETWORK FUNCTIONS =================
def fetch_url(url: str):
    try:
        start = time.time()
        resp = requests.get(url, timeout=DEFAULT_TIMEOUT, verify=False, allow_redirects=True)
        elapsed = time.time() - start
        return resp, elapsed, None
    except Exception as e:
        return None, None, str(e)


def get_base_url(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    return f"{scheme}://{parsed.netloc}"


def get_certificate_info(url: str):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return "Not HTTPS – No SSL/TLS certificate.", None, None

    hostname = parsed.hostname
    port = parsed.port or 443

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=DEFAULT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        not_after = cert.get("notAfter")
        if not not_after:
            return "Certificate present – expiry date not available.", None, None

        exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_left = (exp_date - datetime.utcnow()).days
        msg = f"Valid until {exp_date} (UTC) — {days_left} day(s) remaining."
        return msg, days_left, None

    except Exception as e:
        return None, None, str(e)


IMPORTANT_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
]

SENSITIVE_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.env",
    "/.git/config",
    "/backup.zip",
    "/db.sql",
    "/backup.sql",
]


def check_sensitive_paths(base_url: str):
    found = []
    for path in SENSITIVE_PATHS:
        url = base_url.rstrip("/") + path
        try:
            resp = requests.get(url, timeout=DEFAULT_TIMEOUT, verify=False)
            if resp.status_code < 400 and len(resp.text) > 0:
                found.append((path, resp.status_code))
        except Exception:
            continue
    return found


def analyse_cookies(resp: requests.Response):
    set_cookie_hdr = resp.headers.get("Set-Cookie")
    if not set_cookie_hdr:
        return []

    cookies_list = []
    parts = set_cookie_hdr.split(", ")
    for part in parts:
        segments = [s.strip() for s in part.split(";")]
        name_val = segments[0].split("=", 1)
        if len(name_val) == 2:
            name, value = name_val
        else:
            name, value = name_val[0], ""

        flags = [s.lower() for s in segments[1:]]

        cookies_list.append({
            "Name": name,
            "Length": len(value),
            "Secure": "Yes" if "secure" in flags else "No",
            "HttpOnly": "Yes" if "httponly" in flags else "No",
            "SameSite": next((s.split("=")[1] for s in segments if s.lower().startswith("samesite=")), "Not set"),
        })
    return cookies_list


def detect_login(html: str):
    soup = BeautifulSoup(html, "html.parser")
    return soup.find("input", {"type": "password"}) is not None


# ================= UI START =================

st.title("🛡 CyberscanX – Website Inspector")
st.caption("Factual Web Analysis Tool — No guessing. No false claims. Only real observations.")

mode = st.sidebar.selectbox("Mode", ["Website Inspection", "About"])


# ================= MAIN ANALYZER =================
if mode == "Website Inspection":
    url = st.text_input("Enter Website URL", placeholder="https://example.com")

    if st.button("Start Analysis"):
        if not url:
            st.error("Please enter a valid URL.")
        else:
            with st.spinner("Fetching webpage..."):
                resp, elapsed, error = fetch_url(url)

            if resp is None:
                st.error(f"Error fetching URL: {error}")
            else:
                html = resp.text
                base = get_base_url(url)

                st.subheader("1. Basic Info")
                c1, c2, c3 = st.columns(3)
                with c1:
                    st.metric("HTTP Status", resp.status_code)
                with c2:
                    st.metric("Time (s)", f"{elapsed:.2f}")
                with c3:
                    st.metric("Size (bytes)", len(html))

                st.write("Meaning:", get_status_meaning(resp.status_code))
                st.write("Server:", resp.headers.get("Server", "Not provided"))
                st.write("X-Powered-By:", resp.headers.get("X-Powered-By", "Not provided"))

                st.subheader("2. HTTPS Certificate")
                cert_summary, cert_days, cert_err = get_certificate_info(url)
                if cert_err:
                    st.warning(f"Could not inspect certificate: {cert_err}")
                else:
                    st.info(cert_summary)

                st.subheader("3. Important Security Headers")
                headers_data = []
                for h in IMPORTANT_HEADERS:
                    val = resp.headers.get(h)
                    headers_data.append({"Header": h, "Present": "Yes" if val else "No", "Value": val or "-"})
                st.table(headers_data)

                st.subheader("4. Cookies")
                cookies = analyse_cookies(resp)
                if cookies:
                    st.table(cookies)
                else:
                    st.write("No cookie headers detected.")

                st.subheader("5. Login Form Detection")
                if detect_login(html):
                    st.info("Password field detected — login page exists.")
                else:
                    st.write("No password field detected.")

                st.subheader("6. Sensitive File Discovery")
                found = check_sensitive_paths(base)
                if found:
                    st.error("Potential exposed files discovered:")
                    st.table(found)
                else:
                    st.success("No common sensitive files accessible.")

                st.markdown("---")
                st.caption("This tool only performs read-only observation. No active attack or exploitation carried out.")


# ================= ABOUT SECTION =================
else:
    st.subheader("About CyberscanX – Website Inspector")
    st.write("""
    This tool performs factual, external web analysis to help developers understand what their site exposes
    over HTTP. It does not guess technologies or produce fake risk scores.
    
    **Outputs include:**
    - HTTP Status meaning
    - HTTPS Certificate expiry
    - Security Headers presence
    - Cookie security flags (Secure, HttpOnly, SameSite)
    - Login form detection
    - Exposed sensitive path check

    **Developer:** Lord Naveen 😎
    """)

