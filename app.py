# safe logo loading (use in your app.py)
import streamlit as st
from PIL import Image
import os

# Option A: relative repo file (recommended for Streamlit Cloud)
logo_candidates = [
    "logo.png",  # put logo.png in same repo folder as app.py
    "/mnt/data/08af1f3f-86aa-4b6a-a3d4-89f5b9a41ee4.png",  # local path (dev only)
]

logo_path = None
for p in logo_candidates:
    if os.path.exists(p):
        logo_path = p
        break

if logo_path:
    try:
        img = Image.open(logo_path)
        st.image(img, width=68)
    except Exception as e:
        st.markdown("## CyberscanX — SQL Injection Scanner")
        st.write("Logo failed to load (image file may be corrupted).")
else:
    # fallback UI so the app doesn't crash
    st.markdown('<div style="font-size:22px;font-weight:700">CyberscanX — SQL Injection Scanner</div>', unsafe_allow_html=True)
    st.markdown('<div style="color:#6b7280">Educational demo — use only on legal targets</div>', unsafe_allow_html=True)
