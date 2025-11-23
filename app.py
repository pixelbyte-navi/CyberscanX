import streamlit as st
import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

st.set_page_config(page_title="CyberscanX", page_icon="🛡️", layout="wide")

# -------- SQL PAYLOADS ----------
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
    "warning",
    "syntax error",
]

# ------- Helper Functions -------

def get_params(url):
    parsed = urlparse(url)
    return list(parse_qs(parsed.query).keys())

def build_url(original_url, param_name, value):
    parsed = urlparse(original_url)
    query = parse_qs(parsed.query)
    query[param_name] = value
    new_query = urlencode(query, doseq=True)
    parsed = parsed._replace(query=new_query)
    return urlunparse(parsed)

def send_request(target, timeout):
    try:
        start = time.time()
        resp = requests.get(target, timeout=timeout, verify=False)
        return resp, time.time() - start, None
    except Exception as e:
        return None, None, str(e)


# ------------ UI Layout -----------
st.title("🛡️ CyberscanX")
st.caption("SQL Sentinel : Automated SQL Injection & Vulnerability Finder\nFor legal testing & educational use only.")

mode = st.sidebar.selectbox("Select Scan Mode", ["SQL Injection Scan", "Security Header Scan", "About Project"])

# =============================================
# =============== SQL Injection Scan ===========
# =============================================

if mode == "SQL Injection Scan":

    st.subheader("SQL Injection Detection")

    url = st.text_input("Enter target URL with parameter (example: https://testphp.vulnweb.com/artists.php?artist=1)",
                        placeholder="https://example.com/product.php?id=1")

    timeout = st.number_input("Timeout (seconds)", min_value=2, max_value=30, value=8)

    if st.button("Start Scan"):

        if not url:
            st.error("Please enter a valid URL")
        else:
            params = get_params(url)

            if not params:
                st.warning("❗ No parameters found in the URL. SQL Injection Scan Not Applicable.")
                st.info("Example of parameter: https://example.com/item.php?id=1  → id is parameter")
            else:
                param = params[0]
                st.info(f"Target parameter detected: **{param}**")

                baseline_resp, baseline_time, err = send_request(url, timeout)

                if baseline_resp is None:
                    st.error(f"Request failed: {err}")
                else:
                    baseline_len = len(baseline_resp.text)
                    st.success(f"Baseline Response: HTTP {baseline_resp.status_code} | Size: {baseline_len} bytes")

                    results = []
                    for payload in SQLI_PAYLOADS:
                        test_value = payload
                        attack_url = build_url(url, param, test_value)

                        resp, t, error = send_request(attack_url, timeout)

                        if resp is None:
                            results.append([payload, "Failed", error])
                        else:
                            suspicious = False
                            reason = ""

                            length_diff = abs(len(resp.text) - baseline_len)
                            if length_diff > 100:
                                suspicious = True
                                reason += f"Response size changed by {length_diff} bytes. "

                            if any(e in resp.text.lower() for e in ERROR_KEYWORDS):
                                suspicious = True
                                reason += "SQL error keyword found. "

                            results.append([
                                payload,
                                resp.status_code,
                                "YES" if suspicious else "NO",
                                reason if reason else "No indicators"
                            ])

                    st.subheader("Scan Results")
                    st.table(results)

                    if any(r[2] == "YES" for r in results):
                        st.error("🚨 Possible SQL Injection Indicators Found — Manual verification recommended.")
                    else:
                        st.success("✅ No strong SQL injection indicators detected.")

# =============================================
# ============== Header Scan ==================
# =============================================

elif mode == "Security Header Scan":

    st.subheader("Security Header Analysis")

    url = st.text_input("Enter website URL (example: https://amazon.in)")

    if st.button("Check Headers"):

        try:
            resp = requests.get(url, timeout=10, verify=False)
            st.write(f"Status: {resp.status_code}")

            important_headers = [
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Strict-Transport-Security",
                "Referrer-Policy",
            ]

            header_result = []
            for h in important_headers:
                header_result.append([h, "Present" if h in resp.headers else "Missing"])

            st.table(header_result)

        except Exception as e:
            st.error(f"Error: {e}")

# =============================================
# =============== About ========================
# =============================================

else:
    st.subheader("About SQL Sentinel / CyberscanX")
    st.write("""
    CyberscanX is a lightweight automated web vulnerability scanner built for educational purposes.
    It performs SQL injection indicator testing and security header analysis.

    **Legal Disclaimer:** Use only on websites you own or have written permission to test.
    Unauthorized testing is illegal.
    """)
