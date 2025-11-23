# app.py
# CyberscanX Lite – Simple SQL Injection checker with built-in logic
# No SQLMap, no external APIs. Just Python + requests + Flask.

from flask import Flask, request, render_template_string
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

app = Flask(__name__)

# ---------------- UI TEMPLATE (kept inside this file) ---------------- #

HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>CyberscanX Lite – SQL Injection Checker</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
  <style>
    body {
      background: radial-gradient(circle at top left, #020617, #020617, #111827);
      color: #e5e7eb;
      min-height: 100vh;
    }
    .brand-title { font-weight: 700; letter-spacing: .18em; text-transform: uppercase; }
    .card-main {
      background: rgba(15,23,42,.96);
      border-radius: 18px;
      border: 1px solid rgba(148,163,184,.35);
      box-shadow: 0 24px 60px rgba(15,23,42,.9);
    }
    .pill { border-radius: 999px; padding: .3rem .9rem; font-size: .7rem;
            text-transform: uppercase; letter-spacing: .1em; }
    .pill-bad { background: linear-gradient(135deg,#f97316,#ef4444); }
    .pill-good { background: linear-gradient(135deg,#22c55e,#16a34a); }
    code { font-size: .8rem; background:#020617; padding:.25rem .4rem; border-radius:6px;}
    .footer-text { font-size: .75rem; color:#9ca3af; }
  </style>
</head>
<body>
  <div class="container py-5">
    <header class="text-center mb-4">
      <div class="brand-title text-primary-emphasis mb-1">CyberscanX</div>
      <h1 class="h4 fw-semibold text-light mb-1">SQL Injection Surface Scan (Lite)</h1>
      <p class="text-secondary small mb-0">
        Quick check for common SQL injection behaviour. For authorised testing only.
      </p>
    </header>

    <main class="row justify-content-center">
      <div class="col-12 col-md-8 col-lg-7">
        <div class="card-main p-4 p-md-5">
          <form method="post" class="mb-4">
            <label for="url" class="form-label small text-uppercase text-secondary mb-1">
              Target URL
            </label>
            <div class="input-group input-group-lg mb-2">
              <input type="url" class="form-control" id="url" name="url"
                     placeholder="https://example.com/item.php?id=1"
                     value="{{ url or '' }}" required>
              <button class="btn btn-primary px-4" type="submit">Scan</button>
            </div>
            <div class="form-text text-secondary small">
              Only scan apps you own or have written permission to test.
            </div>
          </form>

          {% if result %}
            {% if result.error %}
              <div class="alert alert-danger small mb-0">
                <strong>Error:</strong> {{ result.error }}
              </div>
            {% else %}
              {% if not result.issues %}
                <div class="d-flex align-items-center mb-2">
                  <span class="pill pill-good me-2">No obvious SQLi</span>
                  <span class="small text-secondary">
                    No suspicious behaviour found in this quick test.
                  </span>
                </div>
                <p class="small text-secondary mb-0">
                  This is a lightweight heuristic scanner. A clean result here does not
                  guarantee the application is fully secure, but it’s a good first pass.
                </p>
              {% else %}
                <div class="d-flex align-items-center mb-3">
                  <span class="pill pill-bad me-2">Possible SQLi</span>
                  <span class="small text-warning">
                    One or more parameters responded strangely to SQL-style payloads.
                  </span>
                </div>

                {% for issue in result.issues %}
                  <div class="border border-secondary rounded-3 p-3 mb-3 bg-dark bg-opacity-25 small">
                    <div class="mb-1">
                      <span class="text-secondary text-uppercase">Parameter:</span>
                      <span class="badge bg-secondary-subtle text-light">
                        {{ issue.param }}
                      </span>
                    </div>
                    <div class="mb-1">
                      <span class="text-secondary text-uppercase">Payload:</span>
                      <code>{{ issue.payload }}</code>
                    </div>
                    <div class="mb-1">
                      <span class="text-secondary text-uppercase">Observation:</span>
                      <span>{{ issue.reason }}</span>
                    </div>
                    <div class="mb-0 text-secondary">
                      (Differences in status/length suggest the backend may be evaluating the input.)
                    </div>
                  </div>
                {% endfor %}
              {% endif %}
            {% endif %}
          {% else %}
            <p class="small text-secondary mb-0">
              Paste a URL with query parameters (e.g. <code>?id=1</code>) and hit Scan.
              CyberscanX will try a few classic SQL injection strings and compare responses.
            </p>
          {% endif %}
        </div>

        <p class="footer-text text-center mt-3">
          CyberscanX Lite · Heuristic SQL injection surface scan · Not a replacement for full pentesting.
        </p>
      </div>
    </main>
  </div>
</body>
</html>
"""

# ---------------- SIMPLE SQLi CHECK LOGIC (inside this file) ---------------- #

COMMON_PAYLOADS = [
    "'", "\"", "1'", "' OR '1'='1", "1 OR 1=1", "1'--", "') OR ('1'='1"
]


def build_url_with_param(original_url, param_name, new_value):
    """Return new URL with one query parameter changed."""
    parsed = urlparse(original_url)
    query = parse_qs(parsed.query)
    query[param_name] = [new_value]
    new_query = urlencode(query, doseq=True)
    new_parsed = parsed._replace(query=new_query)
    return urlunparse(new_parsed)


def basic_sqli_scan(target_url, timeout=10):
    """
    Very lightweight SQLi detector:
      - Fetch baseline response
      - For each parameter, inject common SQLi payloads
      - Compare status code + response length
      - If big changes → flag as suspicious
    """
    try:
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)

        if not params:
            return {"issues": [], "note": "No query parameters found to test."}

        # Baseline
        base_resp = requests.get(target_url, timeout=timeout)
        base_len = len(base_resp.text)
        base_status = base_resp.status_code

        issues = []

        for param, values in params.items():
            original_value = values[0]

            for payload in COMMON_PAYLOADS:
                test_value = f"{original_value}{payload}"
                test_url = build_url_with_param(target_url, param, test_value)

                try:
                    resp = requests.get(test_url, timeout=timeout)
                except Exception:
                    continue

                length_diff = abs(len(resp.text) - base_len)
                status_changed = resp.status_code != base_status

                # Heuristic thresholds – you can tune these
                if status_changed or length_diff > base_len * 0.25:
                    issues.append({
                        "param": param,
                        "payload": test_value,
                        "reason": f"Status changed ({base_status} → {resp.status_code}) "
                                  f"or length changed significantly ({base_len} → {len(resp.text)})."
                    })
                    # one suspicious payload per parameter is enough
                    break

        return {"issues": issues}

    except Exception as e:
        return {"error": str(e)}


# ---------------- FLASK ROUTE ---------------- #

@app.route("/", methods=["GET", "POST"])
def index():
    url = None
    result = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not url:
            result = {"error": "Please provide a valid URL."}
        else:
            result = basic_sqli_scan(url)

    return render_template_string(HTML_TEMPLATE, url=url, result=result)


if __name__ == "__main__":
    # Only requirement on any system: Python + `pip install flask requests`
    app.run(debug=True)
