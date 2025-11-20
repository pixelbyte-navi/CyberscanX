import streamlit as st
import pandas as pd
import time
from sql_sentinel_module import scan_target

st.set_page_config(page_title="CyberscanX", layout="centered")
st.title("🔍 CyberscanX — SQL Injection Scanner (Educational)")
st.markdown("Use this tool **only on legal demo targets** like DVWA, JuiceShop, WebGoat.")
st.info("❗ This is a basic educational scanner. Do NOT scan public websites.")

with st.form("scan_form"):
    target = st.text_input(
        "Enter target URL (DVWA / JuiceShop demo only)",
        value="http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"
    )
    timeout = st.number_input("Timeout (seconds)", min_value=2, max_value=60, value=8)
    delay = st.number_input("Delay between requests", min_value=0.0, max_value=2.0, value=0.2)
    run = st.form_submit_button("Run Scan")

if run:
    if not target:
        st.error("Please enter a target URL.")
    else:
        st.info("Scanning... Please wait.")
        progress = st.progress(0)
        status = st.empty()

        # UI progress animation
        for p in range(0, 40, 10):
            progress.progress(p)
            time.sleep(0.05)

        try:
            status.text("Running scanner...")
            findings = scan_target(target, timeout=timeout, delay=delay)
        except Exception as e:
            st.error(f"Scanner error: {e}")
            findings = []

        progress.progress(100)
        status.text("Scan completed.")

        if not findings:
            st.success("No vulnerabilities detected by these basic tests.")
        else:
            st.success(f"Found {len(findings)} potential issues.")
            df = pd.DataFrame(findings)
            st.dataframe(df)

            st.markdown("### 🔎 Details")
            for i, f in enumerate(findings):
                with st.expander(f"{i+1}. {f.get('type','Unknown')}"):
                    st.write("**Parameter/Field:**", f.get("param") or f.get("field") or "N/A")
                    st.write("**Payload Used:**", f.get("payload") or "N/A")
                    st.write("**URL/Action:**", f.get("url") or f.get("action") or "N/A")
                    st.write("**Method:**", f.get("method", "GET"))
                    st.write("**Response Length:**", f.get("response_len") or f.get("resp_len"))
                    if f.get("resp_text"):
                        with st.expander("Show Raw Response"):
                            st.code(f.get("resp_text")[:5000])
