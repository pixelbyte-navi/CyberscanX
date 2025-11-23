import streamlit as st
import requests
import urllib3
import socket
import ssl
import time
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup  # make sure beautifulsoup4 is in requirements.txt

# ----- Basic setup -----
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

st.set_page_config(page_title="CyberscanX", page_icon="🛡️", layout="wide")
DEFAULT_TIMEOUT = 20  # seconds


# ================= Helper functions =================

def get_base_url(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc
    return f"{scheme}://{netloc}"


def fetch_url(url: str):
    try:
        start = time.time()
        resp = requests.get(url, timeout=DEFAULT_TIMEOUT, verify=False)
        elapsed = time.time() - start
        return resp, elapsed, None
    except Exception as e:
        return None, None, str(e)


def detect_static_dynamic(html: str, resp: requests.Response) -> str:
    """Very simple heuristic: NOT perfect, but good for explanation."""
    if resp.cookies:
        return "Likely Dynamic (cookies used)"
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    if any(f.get("method", "").lower() == "post" for f in forms):
        return "Dynamic (POST form detected)"
    text = html.lower()
    hints = ["fetch(", "axios", "xmlhttprequest", "/api/"]
    if any(h in text for h in hints):
        return "Likely Dynamic (JS/API calls detected)"
    return "Likely Static (no obvious dynamic features found)"


def detect_stack_and_framework(html: str, resp: requests.Response):
    """Return (backend_guess, framework_guess, notes_list)."""
    backend = "Unknown"
    framework = "Unknown"
    notes = []

    server = resp.headers.get("Server", "")
    powered = resp.headers.get("X-Powered-By", "")
    html_lower = html.lower()

    # Backend guesses
    if "php" in powered.lower() or ".php" in html_lower or "php" in server.lower():
        backend = "PHP (heuristic)"
    elif "asp.net" in powered.lower() or "asp.net" in server.lower():
        backend = ".NET (ASP.NET) (heuristic)"
    elif "nginx" in server.lower():
        backend = "Possibly PHP/Node (behind Nginx)"
    elif "apache" in server.lower():
        backend = "Possibly PHP/Perl (Apache)"
    elif "python" in powered.lower() or "wsgi" in server.lower():
        backend = "Python (Django/Flask) (heuristic)"
    elif "node" in powered.lower() or "express" in html_lower:
        backend = "Node.js (heuristic)"

    # Framework detection (very rough)
    if "wp-content" in html_lower or "wp-includes" in html_lower:
        framework = "WordPress"
    elif "__next" in html_lower:
        framework = "Next.js (React SSR)"
    elif 'id="root"' in html_lower or 'id="app"' in html_lower:
        framework = "SPA (React/Vue/Angular - heuristic)"
    elif "csrfmiddlewaretoken" in html_lower:
        framework = "Django"
    elif "laravel" in html_lower:
        framework = "Laravel (heuristic)"

    if powered:
        notes.append(f"X-Powered-By header: {powered}")
    if server:
        notes.append(f"Server header: {server}")

    return backend, framework, notes


def get_certificate_info(url: str):
    """Return (summary_str, days_to_expiry or None, error_str or None)."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return "Not an HTTPS URL – no certificate.", None, None

    hostname = parsed.hostname
    port = parsed.port or 443

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=DEFAULT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        not_after = cert.get("notAfter")
        if not not_after:
            return "Certificate information not available.", None, None

        # Example format: 'Jan 15 12:00:00 2026 GMT'
        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_left = (exp - datetime.utcnow()).days
        summary = f"Certificate valid until {exp} (UTC), ~{days_left} day(s) remaining."
        return summary, days_left, None
    except Exception as e:
        return None, None, str(e)


def analyse_cookies(resp: requests.Response):
    """Return (issues_list, summary_str)."""
    cookies = resp.cookies
    set_cookie_hdr = resp.headers.get("Set-Cookie", "")
    issues = []

    if not cookies and not set_cookie_hdr:
        return ["No cookies observed in this response."], "No session/cookie behaviour visible."

    # Check raw Set-Cookie header once for flags
    summary = "Analysed cookie flags from Set-Cookie header."
    sc_lower = set_cookie_hdr.lower()

    if "secure" not in sc_lower:
        issues.append("Some cookies may be missing the Secure flag (should be sent only over HTTPS).")
    if "httponly" not in sc_lower:
        issues.append("Some cookies may be missing the HttpOnly flag (protects against cookie theft via XSS).")
    if "samesite" not in sc_lower:
        issues.append("SameSite attribute not clearly set (helps against CSRF).")

    if not issues:
        issues.append("All main cookie security flags (Secure, HttpOnly, SameSite) appear to be set.")

    return issues, summary


SENSITIVE_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.env",
    "/.git/config",
    "/backup.zip",
    "/db.sql",
    "/backup.sql",
    "/config.php.bak",
    "/.DS_Store",
]


def check_sensitive_paths(base_url: str):
    found = []
    for path in SENSITIVE_PATHS:
        url = base_url.rstrip("/") + path
        try:
            resp = requests.get(url, timeout=DEFAULT_TIMEOUT, verify=False, allow_redirects=True)
            if resp.status_code < 400 and len(resp.text) > 0:
                found.append((path, resp.status_code))
        except Exception:
            continue
    return found


def detect_login_form(html: str):
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    for f in forms:
        inputs = f.find_all("input")
        for i in inputs:
            t = (i.get("type") or "").lower()
            name = (i.get("name") or "").lower()
            if "password" in t or "password" in name:
                return True
    return False


# Simple risk scoring based on findings
def build_risk_summary(
    status_code: int,
    cert_days: int | None,
    sensitive_files,
    cookie_issues,
    static_dynamic_label: str,
) -> tuple[str, int]:
    """
    Return (risk_level, score).
    Higher score = worse. This is just for education.
    """
    score = 0

    if status_code >= 500:
        score += 2
    elif status_code >= 400:
        score += 1

    if cert_days is not None:
        if cert_days < 0:
            score += 3
        elif cert_days < 30:
            score += 1

    if sensitive_files:
        score += 3

    # If cookie_issues mention missing Secure/HttpOnly, add points
    for issue in cookie_issues:
        if "Secure flag" in issue or "HttpOnly" in issue:
            score += 1

    if "Dynamic" in static_dynamic_label:
        score += 1  # dynamic apps naturally more complex / risky

    # Convert score → label
    if score >= 7:
        level = "High"
    elif score >= 4:
        level = "Medium"
    else:
        level = "Low"

    return level, score


# ===================== UI =====================

st.title("🛡️ CyberscanX 2.0 — Web Security Analyzer")
st.caption(
    "SQL Sentinel Project • CyberscanX focuses on high-level, non-destructive web security checks. "
    "Use only on sites you own or have permission to test."
)

mode = st.sidebar.selectbox(
    "Select Mode",
    ["Web Security Analyzer", "About Project"],
)

# -------------------------------------------------
#                   ANALYZER
# -------------------------------------------------
if mode == "Web Security Analyzer":
    st.subheader("Web Technology & Security Overview")

    url = st.text_input(
        "Enter website URL",
        placeholder="https://example.com",
    )

    if st.button("Run Analysis"):
        if not url:
            st.error("Please enter a URL.")
        else:
            with st.spinner("Contacting target and fetching response..."):
                resp, elapsed, error = fetch_url(url)

            if resp is None:
                st.error(f"Error while fetching the URL: {error}")
            else:
                html = resp.text
                base_url = get_base_url(url)

                # ---- Basic info ----
                st.success(f"Response received: HTTP {resp.status_code} in {elapsed:.2f} seconds")
                content_len = len(html)
                server = resp.headers.get("Server", "Unknown")
                x_powered_by = resp.headers.get("X-Powered-By", "Unknown")

                c1, c2, c3 = st.columns(3)
                with c1:
                    st.metric("HTTP Status", resp.status_code)
                with c2:
                    st.metric("Response Time (s)", f"{elapsed:.2f}")
                with c3:
                    st.metric("Content Size (bytes)", content_len)

                st.write(f"**Server header:** {server}")
                st.write(f"**X-Powered-By:** {x_powered_by}")

                # ---- Static vs Dynamic ----
                sd_label = detect_static_dynamic(html, resp)
                st.subheader("Application Nature")
                st.info(f"Based on simple heuristics, this site appears: **{sd_label}**.")

                # ---- Stack & Framework ----
                backend, framework, tech_notes = detect_stack_and_framework(html, resp)
                st.subheader("Technology Fingerprint (Heuristic)")
                st.write(f"**Probable backend stack:** {backend}")
                st.write(f"**Probable framework/CMS:** {framework}")
                if tech_notes:
                    st.markdown("**Evidence:**")
                    for n in tech_notes:
                        st.markdown(f"- {n}")

                # ---- Certificate info ----
                st.subheader("HTTPS Certificate Check")
                cert_summary, days_left, cert_err = get_certificate_info(url)
                if cert_err:
                    st.warning(f"Could not analyse certificate: {cert_err}")
                else:
                    st.write(cert_summary)

                # ---- Cookies / Session ----
                st.subheader("Cookie & Session Security (from this response)")
                cookie_issues, cookie_summary = analyse_cookies(resp)
                st.markdown(f"*{cookie_summary}*")
                for issue in cookie_issues:
                    st.markdown(f"- {issue}")

                # ---- Login form detection ----
                st.subheader("Authentication Surface")
                if detect_login_form(html):
                    st.info("Login/Password form detected on this page (or a related form).")
                else:
                    st.write("No obvious login/password form detected in this specific response.")

                # ---- Sensitive paths / files ----
                st.subheader("Exposed Files & Discovery")
                with st.spinner("Checking for robots.txt, sitemap.xml and common sensitive files..."):
                    sensitive_found = check_sensitive_paths(base_url)

                if sensitive_found:
                    st.error("Potentially interesting/exposed paths were found:")
                    data = []
                    for path, status in sensitive_found:
                        if path in ["/robots.txt", "/sitemap.xml"]:
                            impact = "Informational — may reveal hidden URLs."
                        else:
                            impact = "High — file may expose configuration, backups or source code."
                        data.append(
                            {
                                "Path": path,
                                "HTTP Status": status,
                                "Impact": impact,
                            }
                        )
                    st.table(data)
                else:
                    st.success("No common sensitive files (from the small wordlist) were directly accessible.")

                # ---- Overall risk summary ----
                risk_level, risk_score = build_risk_summary(
                    resp.status_code,
                    days_left,
                    sensitive_found,
                    cookie_issues,
                    sd_label,
                )

                st.subheader("Overall Risk Summary (Heuristic, for learning only)")
                colr1, colr2 = st.columns(2)
                with colr1:
                    st.metric("Calculated Risk Level", risk_level)
                with colr2:
                    st.metric("Risk Score (0 = best)", risk_score)

                st.markdown(
                    "_This risk level is a simple, rule-based estimate for educational purposes only. "
                    "Real security assessments require deeper authenticated testing, code review and "
                    "context about how the application is used._"
                )

# -------------------------------------------------
#                   ABOUT
# -------------------------------------------------
else:
    st.subheader("About SQL Sentinel / CyberscanX 2.0")
    st.markdown(
        """
        **Project Title:** SQL Sentinel : An Automated SQL Injection & Vulnerability Finder  
        **Tool Name:** CyberscanX 2.0 — Web Security Analyzer  

        ### What this tool does
        - Analyses a given web URL and gathers:
          - HTTP status, response time and content size  
          - Static vs Dynamic behaviour (heuristic)  
          - Probable backend stack (PHP, .NET, Python, Node, etc.) and framework (WordPress, Next.js, etc.)  
          - HTTPS certificate validity and days remaining  
          - Cookie and session security flags (Secure, HttpOnly, SameSite)  
          - Presence of login/password forms  
          - Exposure of common files like `robots.txt`, `sitemap.xml`, `.env`, `.git/config`, `backup.sql`, etc.  

        - Produces a **simple Risk Level (Low / Medium / High)** and explanation
          that helps developers understand **what to fix and why**.

        ### Why this is useful
        - Gives **web developers and students** a quick, non-destructive overview of
          how their application looks from an attacker’s perspective.  
        - Helps during **interviews & placements** to demonstrate:
          - Understanding of web security concepts  
          - Ability to build practical tools using Python & Streamlit  
          - Awareness of limitations and ethical boundaries in security testing  

        ### Legal & Ethical Note
        - CyberscanX 2.0 performs only **read-only, non-destructive checks**.  
        - It must be used **only on websites you own or have explicit permission to test**.  
        - Unauthorized scanning may be illegal under computer misuse laws.

        **Developer:** Lord Naveen 😎  
        """
    )
