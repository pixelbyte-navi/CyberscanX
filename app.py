# app.py
# CyberscanX – SQL Injection Scanner with embedded SQLMap API + simple UI

from flask import Flask, request, render_template_string
import requests
import subprocess
import time
import os

app = Flask(__name__)

# Change if you run SQLMap API elsewhere
SQLMAP_API_URL = os.getenv("SQLMAP_API_URL", "http://127.0.0.1:8775")

# -------------------- UI TEMPLATE (HTML inside app.py) -------------------- #
HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>CyberscanX – SQL Injection Scanner</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <!-- Simple CSS via CDN -->
  <link rel="stylesheet"
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
  <style>
    body {
      background: radial-gradient(circle at top left, #0f172a, #020617);
      color: #e5e7eb;
      min-height: 100vh;
    }
    .brand-title {
      font-weight: 700;
      letter-spacing: 0.12em;
      text-transform: uppercase;
    }
    .scan-card {
      background: rgba(15, 23, 42, 0.95);
      border-radius: 16px;
      border: 1px solid rgba(148, 163, 184, 0.25);
      box-shadow: 0 24px 60px rgba(15, 23, 42, 0.9);
    }
    .badge-sqli {
      background: linear-gradient(135deg, #f97316, #ef4444);
    }
    .badge-safe {
      background: linear-gradient(135deg, #22c55e, #16a34a);
    }
    .pill {
      border-radius: 999px;
      padding: 0.35rem 0.85rem;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }
    code {
      font-size: 0.8rem;
      background: rgba(15, 23, 42, 0.9);
      padding: 0.25rem 0.4rem;
      border-radius: 6px;
    }
    .footer-text {
      font-size: 0.75rem;
      color: #9ca3af;
    }
  </style>
</head>
<body>
  <div class="container py-5">
    <header class="mb-4 text-center">
      <div class="brand-title text-primary-emphasis mb-1">CyberscanX</div>
      <h1 class="h3 fw-semibold text-light">SQL Injection Surface Scanner</h1>
      <p class="text-secondary small mb-0">
        Give a URL. We’ll use SQLMap silently in the background and summarise the risk.
      </p>
    </header>

    <main class="row justify-content-center">
      <div class="col-12 col-md-8 col-lg-7">
        <div class="scan-card p-4 p-md-5">
          <form method="post" class="mb-4">
            <label for="url" class="form-label small text-uppercase text-secondary mb-1">
              Target URL
            </label>
            <div class="input-group input-group-lg mb-2">
              <input type="url"
                     class="form-control"
                     id="url"
                     name="url"
                     placeholder="https://example.com/product.php?id=1"
                     value="{{ url or '' }}"
                     required>
              <button class="btn btn-primary px-4" type="submit">
                Scan
              </button>
            </div>
            <div class="form-text text-secondary small">
              Only scan targets you own or have explicit permission to test.
            </div>
          </form>

          {% if result %}
            {% if result.error %}
              <div class="alert alert-danger small">
                <strong>Error:</strong> {{ result.error }}
              </div>
            {% elif not result.vulnerable %}
              <div class="d-flex align-items-center mb-3">
                <span class="pill badge-safe me-2">No SQLi Detected</span>
                <span class="small text-secondary">Based on a quick SQLMap API pass.</span>
              </div>
              {% if result.message %}
                <p class="small text-secondary mb-0">{{ result.message }}</p>
              {% endif %}
            {% else %}
              <div class="d-flex align-items-center mb-3">
                <span class="pill badge-sqli me-2">Possible SQLi</span>
                <span class="small text-warning">One or more inputs appear injectable. Validate manually.</span>
              </div>

              {% for issue in result.issues %}
                <div class="border border-secondary rounded-3 p-3 mb-3 bg-dark bg-opacity-25">
                  <div class="d-flex justify-content-between align-items-center mb-2">
                    <div class="small text-uppercase text-secondary">
                      Parameter
                    </div>
                    <div class="small">
                      <span class="badge rounded-pill bg-secondary-subtle text-light">
                        {{ issue.parameter or "unknown" }}
                      </span>
                    </div>
                  </div>
                  <dl class="row mb-0 small">
                    <dt class="col-4 text-secondary">Injection type</dt>
                    <dd class="col-8">{{ issue.type or "n/a" }}</dd>

                    <dt class="col-4 text-secondary">Backend DBMS</dt>
                    <dd class="col-8">{{ issue.dbms or "unknown" }}</dd>

                    <dt class="col-4 text-secondary">Title</dt>
                    <dd class="col-8">{{ issue.title or "not provided" }}</dd>

                    <dt class="col-4 text-secondary">Sample payload</dt>
                    <dd class="col-8"><code>{{ issue.payload or "n/a" }}</code></dd>
                  </dl>
                </div>
              {% endfor %}
            {% endif %}
          {% else %}
            <p class="small text-secondary mb-0">
              Enter a URL above to start a scan. CyberscanX will not exploit or dump data – it only checks
              if classic SQL injection patterns appear to be possible.
            </p>
          {% endif %}
        </div>

        <p class="footer-text mt-3 text-center">
          Powered by CyberscanX · SQLMap API integration · For educational and authorised security testing only.
        </p>
      </div>
    </main>
  </div>
</body>
</html>
"""

# -------------------- SQLMap API INTEGRATION -------------------- #

def start_sqlmap_api():
    """
    Try to start sqlmapapi in server mode.
    If it's already running, just continue.
    """
    try:
        # Check if API is already reachable
        try:
            r = requests.get(f"{SQLMAP_API_URL}/task/new", timeout=2)
            if r.status_code == 200 and r.json().get("taskid"):
                print("[CyberscanX] SQLMap API already running.")
                return
        except Exception:
            pass

        print("[CyberscanX] Starting SQLMap API server...")
        # Extract port from URL (e.g. "http://127.0.0.1:8775" → "8775")
        port = SQLMAP_API_URL.rsplit(":", 1)[1]
        subprocess.Popen(
            ["sqlmapapi.py", "-s", "-p", port],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(3)
        print("[CyberscanX] SQLMap API start attempted.")
    except Exception as e:
        print(f"[CyberscanX] Could not start SQLMap API: {e}")


def scan_sql_injection(target_url: str, wait_seconds: int = 15):
    """
    Small wrapper around SQLMap's REST API.
    Returns a dict ready for the UI.
    """
    try:
        # 1) Create new task
        r = requests.get(f"{SQLMAP_API_URL}/task/new", timeout=10)
        if r.status_code != 200:
            return {"error": "Could not talk to SQLMap API (task/new failed)."}
        task_id = r.json().get("taskid")
        if not task_id:
            return {"error": "SQLMap did not return a task id."}

        # 2) Start scan
        start_payload = {"url": target_url}
        r = requests.post(
            f"{SQLMAP_API_URL}/scan/{task_id}/start",
            json=start_payload,
            timeout=10
        )
        if r.status_code != 200 or not r.json().get("success"):
            return {"error": "SQLMap could not start the scan for this URL."}

        # 3) Simple wait (no complex loop)
        time.sleep(wait_seconds)

        # 4) Fetch results
        r = requests.get(f"{SQLMAP_API_URL}/scan/{task_id}/data", timeout=10)
        if r.status_code != 200:
            return {"error": "Could not retrieve scan data from SQLMap."}

        data_list = r.json().get("data", [])
        if not data_list:
            return {
                "vulnerable": False,
                "message": "No SQL injection detected in this quick pass, or scan still running."
            }

        issues = []
        for entry in data_list:
            value = entry.get("value", {})
            issues.append({
                "parameter": value.get("parameter"),
                "type": value.get("type"),
                "dbms": value.get("dbms"),
                "title": value.get("title"),
                "payload": value.get("payload"),
            })

        return {
            "vulnerable": True,
            "issues": issues
        }

    except Exception as e:
        return {"error": f"SQLMap API error: {e}"}

# -------------------- FLASK ROUTE -------------------- #

@app.route("/", methods=["GET", "POST"])
def index():
    url = None
    result = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if url:
            result = scan_sql_injection(url)
        else:
            result = {"error": "Please provide a valid URL."}

    return render_template_string(HTML_TEMPLATE, url=url, result=result)


if __name__ == "__main__":
    # Start SQLMap API in background when app starts
    start_sqlmap_api()
    # Launch CyberscanX web UI
    app.run(debug=True)
