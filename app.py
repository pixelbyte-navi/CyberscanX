import streamlit as st
import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import urllib3

# Disable SSL warnings for demo purposes (because we use verify=False)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------- Global Settings ----------
st.set_page_config(page_title="CyberscanX", page_icon="🛡️", layout="wide")

DEFAULT_TIMEOUT = 25  # internal timeout in seconds (no user control)

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


# ---------- Sidebar & Title ----------

st.title("🛡️ CyberscanX")
st.caption(
    "SQL Sentinel : Automated SQL Injection & Vulnerability Finder "
    "— For legal testing & educational use only."
)

mode = st.sidebar.selectbox(
    "Select Scan Mode",
    ["SQL Injection Scan", "Security Header Scan", "About Project"],
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
        "_Example of parameter:_ `https://example.com/item.php?id=1` → `id` is the parameter."
    )

    if st.button("Start Scan"):
        if not url:
            st.error("Please enter a valid URL.")
        else:
            params = get_params(url)

            if not params:
                st.warning("❗ No parameters found in the URL. SQL Injection Scan is NOT applicable.")
                st.info("Hint: Add something like `?id=1` at the end of the URL to test.")
            else:
                param = params[0]  # first parameter by default
                st.info(f"Target parameter detected: **{param}**")

                # Baseline request
                with st.spinner("Sending baseline request..."):
                    baseline_resp, baseline_time, err = send_request(url)

                if baseline_resp is None:
                    st.error(f"Request failed: {err}")
                else:
                    baseline_len = len(baseline_resp.text)
                    st.success(
                        f"Baseline response received: HTTP {baseline_resp.status_code} | "
                        f"Time: {baseline_time:.2f}s | Size: {baseline_len} bytes"
                    )

                    results = []

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

                        # Check response length difference
                        length_diff = abs(len(resp.text) - baseline_len)
                        if length_diff > 100:
                            suspicious = True
                            reasons.append(f"Response size changed by {length_diff} bytes")

                        # Check for SQL error keywords
                        body_lower = resp.text.lower()
                        if any(keyword in body_lower for keyword in ERROR_KEYWORDS):
                            suspicious = True
                            reasons.append("SQL error-like keyword found in response")

                        results.append(
                            {
                                "Payload": payload,
                                "HTTP Status": resp.status_code,
                                "Suspicious": "YES" if suspicious else "NO",
                                "Indicators": "; ".join(reasons) if reasons else "No strong indicators",
                            }
                        )

                    st.subheader("Scan Results")
                    st.table(results)

                    any_suspicious = any(r["Suspicious"] == "YES" for r in results)
                    if any_suspicious:
                        st.error(
                            "🚨 Potential SQL Injection indicators detected. "
                            "Manual security verification is strongly recommended."
                        )
                    else:
                        st.success(
                            "✅ Scan completed. No strong SQL Injection indicators detected "
                            "for the tested parameter based on these checks."
                        )

# =========================================================
#                  SECURITY HEADER SCAN
# =========================================================

elif mode == "Security Header Scan":
    st.subheader("Security Header Analysis")

    url = st.text_input(
        "Enter website URL",
        placeholder="https://example.com",
    )

    if st.button("Check Headers"):
        if not url:
            st.error("Please enter a valid URL.")
        else:
            with st.spinner("Fetching headers..."):
                try:
                    resp = requests.get(url, timeout=DEFAULT_TIMEOUT, verify=False)
                except Exception as e:
                    st.error(f"Error while connecting to the target: {e}")
                else:
                    st.success(f"Response received: HTTP {resp.status_code}")

                    st.write(f"**Server:** {resp.headers.get('Server', 'Unknown')}")
                    st.write(f"**X-Powered-By:** {resp.headers.get('X-Powered-By', 'Unknown')}")

                    important_headers = [
                        "Content-Security-Policy",
                        "X-Frame-Options",
                        "X-Content-Type-Options",
                        "Strict-Transport-Security",
                        "Referrer-Policy",
                    ]

                    header_result = []
                    for h in important_headers:
                        val = resp.headers.get(h)
                        header_result.append(
                            {
                                "Header": h,
                                "Status": "Present" if val else "Missing",
                                "Value": val if val else "-",
                            }
                        )

                    st.subheader("Important Security Headers")
                    st.table(header_result)

                    missing = [h["Header"] for h in header_result if h["Status"] == "Missing"]
                    if missing:
                        st.warning(
                            "Some recommended security headers are missing: "
                            + ", ".join(missing)
                        )
                    else:
                        st.success("All key security headers are present. Good security configuration!")

# =========================================================
#                        ABOUT
# =========================================================

else:
    st.subheader("About SQL Sentinel / CyberscanX")
    st.markdown(
        """
        **SQL Sentinel** is the mini-project title, and **CyberscanX** is the web-based tool
        developed under this project.

        **Purpose**

        - Detect possible SQL Injection indicators in web applications using automated payload testing.  
        - Analyse HTTP responses to find suspicious patterns and SQL error messages.  
        - Review important security headers and highlight missing protections.  

        **Key Notes**

        - This tool is designed for **learning and demonstration**.
        - It performs **lightweight, non-destructive checks** only.
        - Use it **only** on websites you own or have explicit permission to test.  
          Unauthorized security testing may be illegal.

        **Developer:** Lord Naveen 😎  
        """
    )
