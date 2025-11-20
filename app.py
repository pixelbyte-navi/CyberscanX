cat > app.py <<'PY'
import streamlit as st
import pandas as pd
import time
from sql_sentinel_module import scan_target

st.set_page_config(page_title="CyberscanX", layout="centered")
st.title("CyberscanX — Educational SQL Scanner")
st.markdown("Scan intentionally vulnerable demo apps (DVWA, JuiceShop, WebGoat). **Do not scan public websites.**")
st.markdown("> Disclaimer: Use this tool only on systems you own or have explicit permission to test.")

with st.form("scan_form"):
    target = st.text_input("Target URL (include query parameters)", value="http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit")
    timeout = st.number_input("Timeout (s)", min_value=2, max_value=60, value=8)
    delay = st.number_input("Delay between requests (s)", min_value=0.0, max_value=2.0, value=0.2)
    submit = st.form_submit_button("Run Scan (Local Demo Only)")

if submit:
    if not target:
        st.error("Please provide a target URL (use a local demo).")
    else:
        st.info("Starting scan — results will be displayed below (no download).")
        progress = st.progress(0)
        status = st.empty()
        status.text("Preparing scanner...")
        # small UX progress simulation
        for p in range(0, 25, 5):
            progress.progress(p)
            time.sleep(0.03)

        try:
            status.text("Running scanner...")
            findings = scan_target(target, timeout=timeout, delay=delay)
        except Exception as e:
            st.error(f"Scanner error: {e}")
            findings = []

        progress.progress(100)
        status.text("Scan finished.")

        if not findings:
            st.success("No potential issues found by these basic heuristics. (Not a proof of safety.)")
        else:
            st.success(f"Found {len(findings)} potential issues.")
            df = pd.DataFrame(findings)
            # show a compact table
            st.dataframe(df)

            st.markdown("---")
            st.markdown("### Detailed findings")
            for i, f in enumerate(findings):
                title = f"{i+1}. {f.get('type','')}"
                with st.expander(title):
                    st.write("**Parameter / Field:**", f.get("param") or f.get("field") or "-")
                    st.write("**Payload used:**", f.get("payload") or "-")
                    st.write("**URL / Action:**", f.get("url") or f.get("action") or "-")
                    st.write("**Method:**", f.get("method","GET"))
                    st.write("**Response length:**", f.get("response_len") or f.get("resp_len") or "-")
                    if f.get("resp_text"):
                        with st.expander("Raw response (first 5000 chars)"):
                            st.code(f.get("resp_text","")[:5000])
                    # replay example
                    example = f.get("url") or f.get("action") or ""
                    if example:
                        st.markdown("**Replay (curl):**")
                        st.code(f'curl -s -k "{example}"')
PY
