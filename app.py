import streamlit as st
import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import urllib3

# Disable SSL warnings because we use verify=False for demo/testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------- Global Settings ----------
st.set_page_config(page_title="CyberscanX", page_icon="🛡️", layout="wide")
DEFAULT_TIMEOUT = 25  # internal timeout in seconds

# ---------- SQLi Payloads & Error Keywords ----------
SQLI_PAYLOADS = [
    "1' OR '1'='1",
    "1'--",
    "1 OR 1=1",
    "1');--",
]

ERROR_KEYWORDS = [
    "sql syntax",
    "mysql",
    "mysqli",
    "odbc",
    "pdoexception",
    "unclosed quotation",
    "syntax error",
    "warning: mysql",
    "native client",
]

# ---------- Helper Functions ----------

def get_params(url: str):
    """Extract query parameter names from a URL."""
    parsed = urlparse(url)
    return list(parse_qs(parsed.query, keep_blank_values=True).keys())


def build_url(original_url: str, param_name: str, value: str) -> str:
    """Return a new URL with one query parameter changed to a new value."""
    parsed = urlparse(original_url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[param_name] = [value]
    new_query = urlencode(query, doseq=True)
    new_parsed = parsed._replace(query=new_query)
    return urlunparse(new_parsed)


def send_request(target: str):
    """Send a GET request with fixed timeout and SSL verification disabled."""
    try:
        start = time.time()
        resp = requests.get(target, timeout=DEFAULT_TIMEOUT, verify=False)
        elapsed = time.time() - start
        return resp, elapsed, None
    except Exception as e:
        return None, None, str(e)


def calculate_header_risk(headers: dict, status_code: int, set_cookie_header: str):
    """
    Very simple rule-based risk scoring for interview/demo.
    Returns (risk_level, score, issues_list).
    """
    issues = []

    csp = headers.get("Content-Security-Policy")
    xfo = headers.get("X-Frame-Options")
    xcto = headers.get("X-Content-Type-Options")
    hsts = headers.get("Strict-Transport-Security")
    refpol = headers.get("Referrer-Policy")

    score = 0

    # Missing important headers
    if not csp:
        score += 3
        issues.append("Content-Security-Policy header is missing (helps prevent XSS).")
    if not xfo:
        score += 2
        issues.append("X-Frame-Options header is missing (helps prevent clickjacking).")
    if not xcto:
        score += 2
        issues.append("X-Content-Type-Options header is missing (helps prevent MIME sniffing).")
    if not hsts:
        score += 2
        issues.append("Strict-Transport-Security header is missing (enforces HTTPS).")
    if not refpol:
        score += 1
        issues.append("Referrer-Policy header is missing (controls info leakage in referer).")

    # Check cookie security flags in Set-Cookie header (very rough)
    cookie_info = ""
    if set_cookie_header:
        sc_lower = set_cookie_header.lower()
        if "secure" not in sc_lower:
            score += 1
            issues.append("Some cookies may be missing the Secure flag.")
        if "httponly" not in sc_lower:
            score += 1
            issues.append("Some cookies may be missing the HttpOnly flag.")
        if "samesite" not in sc_lower:
            issues.append("SameSite attribute not visible for cookies (CSRF protection).")
        cookie_info = "Cookie security flags analysed."
    else:
        cookie_info = "No Set-Cookie header observed in this response."

    # HTTP status influence
    if status_code >= 500:
        score += 1
        issues.append("Server returned 5xx error for this request (may be an error page or protection layer).")

    # Determine risk level from score (just for education, not real-world guarantee)
    if score >= 7:
        risk = "High"
    elif score >= 4:
        risk = "Medium"
    else:
        risk = "Low"

    if not issues:
        issues.append("No major missing security headers detected in this response.")

    return risk, score, issues, cookie_info


# ---------- Sidebar & Title ----------
st.title("🛡️ CyberscanX")
st.caption(
    "SQL Sentinel : Automated SQL Injection & Vulnerability Finder — "
    "For legal testing & educational use only."
)

mode = st.sidebar.selectbox(
    "Select Scan Mode",
    ["SQL Injection Scan", "Security Headers & Risk Summary", "About Project"],
)

# =========================================================
#                  SQL INJECTION SCAN
# =========================================================
if mode == "SQL Injection Scan":
    st.subheader("SQL Injection Detection")

    url = st.text_input(
        "Enter target URL with parameter",
        placeholder="https://example.com/product.php?id=1",
    )

    st.markdown(
        "_Example:_ `https://example.com/item.php?id=1` → `id` is the parameter."
    )

    if st.button("Start SQL Injection Scan"):
        if not url:
            st.error("Please enter a valid URL.")
        else:
            params = get_params(url)

            if not params:
                st.warning("❗ No parameters found in the URL. SQL Injection Scan is NOT applicable.")
                st.info("Hint: Add something like `?id=1` at the end of the URL to test.")
            else:
                param = params[0]  # testing first parameter by default
                st.info(f"Target parameter detected: **{param}**")

                # Baseline request
                with st.spinner("Sending baseline request..."):
                    baseline_resp, baseline_time, err = send_request(url)

                if baseline_resp is None:
                    st.error(f"Request failed: {err}")
                else:
                    baseline_len = len(baseline_resp.text)
                    st.success(
                        f"Baseline response: HTTP {baseline_resp.status_code} | "
                        f"Time: {baseline_time:.2f}s | Size: {baseline_len} bytes"
                    )

                    results = []
                    suspicious_count = 0

                    for payload in SQLI_PAYLOADS:
                        attack_url = build_url(url, param, payload)

                        with st.spinner(f"Testing payload: `{payload}`"):
                            resp, elapsed, error = send_request(attack_url)

                        if resp is None:
                            results.append(
                                {
                                    "Payload": payload,
                                    "HTTP Status": "Request Failed",
                                    "Suspicious": "N/A",
                                    "Indicators": error or "No response",
                                }
                            )
                            continue

                        suspicious = False
                        reasons = []

                        # Response length difference
                        length_diff = abs(len(resp.text) - baseline_len)
                        if length_diff > 100:
                            suspicious = True
                            reasons.append(f"Response size changed by {length_diff} bytes.")

                        # SQL error keywords
                        body_lower = resp.text.lower()
                        if any(keyword in body_lower for keyword in ERROR_KEYWORDS):
                            suspicious = True
                            reasons.append("SQL error-like keyword found in response.")

                        if suspicious:
                            suspicious_count += 1

                        results.append(
                            {
                                "Payload": payload,
                                "HTTP Status": resp.status_code,
                                "Suspicious": "YES" if suspicious else "NO",
                                "Indicators": " ".join(reasons) if reasons else "No strong indicators.",
                            }
                        )

                    st.subheader("SQL Injection Scan Results")
                    st.table(results)

                    # Simple risk summary
                    if suspicious_count > 0:
                        st.error(
                            f"🚨 Potential SQL Injection indicators detected for {suspicious_count} payload(s).\n\n"
                            "This does NOT confirm a full exploit, but strongly suggests that the "
                            "input handling should be reviewed and parameterized queries / prepared "
                            "statements should be used."
                        )
                        st.markdown(
                            "- Map to **OWASP Top 10: A03:2021 – Injection**  \n"
                            "- Recommended actions: input validation, prepared statements, ORM usage, "
                            "and disabling verbose error messages."
                        )
                    else:
                        st.success(
                            "✅ Scan completed. No strong SQL Injection indicators were observed "
                            "for the tested parameter based on these non-destructive checks."
                        )
                        st.markdown(
                            "_Note: Absence of indicators in this test does not guarantee complete security. "
                            "Manual code review and deeper testing are still recommended in real-world audits._"
                        )

# =========================================================
#          SECURITY HEADERS & RISK SUMMARY
# =========================================================
elif mode == "Security Headers & Risk Summary":
    st.subheader("Security Headers & Risk Summary")

    url = st.text_input(
        "Enter website URL",
        placeholder="https://example.com",
    )

    if st.button("Analyse Security Headers"):
        if not url:
            st.error("Please enter a valid URL.")
        else:
            with st.spinner("Contacting target and fetching headers..."):
                try:
                    resp, elapsed, error = send_request(url)
                except Exception as e:
                    resp, elapsed, error = None, None, str(e)

            if resp is None:
                st.error(f"Error while connecting to the target: {error}")
            else:
                st.success(f"Response received: HTTP {resp.status_code} in {elapsed:.2f}s")

                content_length = len(resp.text)
                server = resp.headers.get("Server", "Unknown")
                x_powered_by = resp.headers.get("X-Powered-By", "Unknown")
                set_cookie_header = resp.headers.get("Set-Cookie", "")

                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("HTTP Status", resp.status_code)
                with col2:
                    st.metric("Response Time (s)", f"{elapsed:.2f}")
                with col3:
                    st.metric("Content Size (bytes)", content_length)

                st.write(f"**Server:** {server}")
                st.write(f"**X-Powered-By:** {x_powered_by}")

                # Important headers
                important_headers = [
                    "Content-Security-Policy",
                    "X-Frame-Options",
                    "X-Content-Type-Options",
                    "Strict-Transport-Security",
                    "Referrer-Policy",
                ]

                header_rows = []
                header_map = {}
                for h in important_headers:
                    val = resp.headers.get(h)
                    status = "Present" if val else "Missing"
                    header_rows.append(
                        {
                            "Header": h,
                            "Status": status,
                            "Value": val if val else "-",
                        }
                    )
                    header_map[h] = val

                # Calculate simple risk
                risk_level, risk_score, issues, cookie_info = calculate_header_risk(
                    header_map, resp.status_code, set_cookie_header
                )

                st.subheader("Overall Security Risk Summary")
                st.info(cookie_info)

                col_r1, col_r2 = st.columns(2)
                with col_r1:
                    st.metric("Calculated Risk Level", risk_level)
                with col_r2:
                    st.metric("Risk Score (0 = best)", risk_score)

                st.markdown("**Key Observations:**")
                for item in issues:
                    st.markdown(f"- {item}")

                st.subheader("Detailed Security Header View")
                st.table(header_rows)

                st.markdown(
                    "_This risk level is a simple educational estimate based only on HTTP response "
                    "headers and cookie flags. Real-world security posture depends on many additional "
                    "factors such as authentication, code quality, server hardening, and network controls._"
                )

# =========================================================
#                        ABOUT
# =========================================================
else:
    st.subheader("About SQL Sentinel / CyberscanX")
    st.markdown(
        """
        **SQL Sentinel** is the mini-project title, and **CyberscanX** is the web-based tool
        developed under this project.

        ### What CyberscanX Does
        - Performs **automated SQL Injection indicator testing** on URLs with parameters.  
        - Analyses **HTTP response headers** and **cookie flags** to highlight missing
          security controls.  
        - Calculates a simple **Security Risk Level (High / Medium / Low)** for educational
          understanding and quick reporting.

        ### Why it is useful for interviews & placements
        - Shows that you understand **OWASP Top 10 (Injection, Security Misconfiguration)**.  
        - Demonstrates ability to build a **real web security tool** using Python & Streamlit.  
        - Generates **clear, visual results** (tables, metrics, risk levels) that can be shown
          in demos and PPTs.

        ### Legal Disclaimer
        - Use CyberscanX **only** on websites you own or have explicit permission to test.  
        - The tool is intentionally **lightweight and non-destructive**, designed for labs,
          demos, and learning.

        **Developer:** Lord Naveen 😎  
        """
    )
