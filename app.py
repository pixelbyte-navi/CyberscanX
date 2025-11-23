# app.py
# Very simple CyberscanX + SQLMap API integration
# -----------------------------------------------
# 1) Start SQLMap API in a separate terminal:
#    sqlmapapi.py -s
#
# 2) Run this app:
#    python app.py
#
# 3) Open: http://127.0.0.1:5000

from flask import Flask, render_template, request
import requests
import time

app = Flask(__name__)

# Change this only if your SQLMap API runs on a different host/port
SQLMAP_API_URL = "http://127.0.0.1:8775"


def scan_sql_injection(target_url: str):
    """
    Very simple wrapper around SQLMap API.
    Returns a dict with:
      - error: if something went wrong
      - vulnerable: True/False
      - issues: list of found SQLi issues (if any)
    """
    try:
        # 1) Create a new task
        new_task = requests.get(f"{SQLMAP_API_URL}/task/new").json()
        task_id = new_task.get("taskid")

        if not task_id:
            return {"error": "SQLMap: could not create task."}

        # 2) Start scan (basic options only to keep it simple)
        start_scan = requests.post(
            f"{SQLMAP_API_URL}/scan/{task_id}/start",
            json={"url": target_url}
        ).json()

        if not start_scan.get("success"):
            return {"error": "SQLMap: could not start scan."}

        # 3) Wait a bit for scan to run (very simple, no complex polling)
        time.sleep(15)  # you can change to 10/20 seconds if you want

        # 4) Get scan data
        scan_data = requests.get(
            f"{SQLMAP_API_URL}/scan/{task_id}/data"
        ).json()

        data_list = scan_data.get("data", [])

        # No data = no SQLi found (or scan still running)
        if not data_list:
            return {
                "vulnerable": False,
                "message": "No SQL injection detected (or scan not finished)."
            }

        # SQLMap returns a list; each entry has 'value' with details
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


@app.route("/", methods=["GET", "POST"])
def index():
    scan_result = None
    url = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()

        if url:
            # Call our simple SQLMap wrapper
            scan_result = scan_sql_injection(url)
        else:
            scan_result = {"error": "Please enter a URL."}

    # Render one template for both GET and POST
    return render_template("index.html", url=url, scan_result=scan_result)


if __name__ == "__main__":
    app.run(debug=True)
