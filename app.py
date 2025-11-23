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
    if not xfo
