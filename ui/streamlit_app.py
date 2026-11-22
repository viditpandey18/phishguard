"""Minimal paste-and-scan UI (Streamlit). Talks to the REST API.

    PHISHGUARD_API=http://localhost:8000 streamlit run ui/streamlit_app.py

Safety: user content and API evidence are rendered as *plain text* only
(st.text / st.code, never unsafe_allow_html), and URLs come back defanged.
"""

from __future__ import annotations

import os

import requests
import streamlit as st

API = os.getenv("PHISHGUARD_API", "http://localhost:8000")
API_KEY = os.getenv("PHISHGUARD_API_KEY", "")
BADGE = {"safe": "🟢 SAFE", "suspicious": "🟠 SUSPICIOUS", "phishing": "🔴 PHISHING", "scam": "🔴 SCAM"}

st.set_page_config(page_title="PhishGuard", page_icon="🛡️", layout="centered")
st.title("🛡️ PhishGuard")
st.caption("Paste an SMS/WhatsApp message, a full email (headers + body) or a URL. Links are never opened.")

mode = st.radio("Input type", ["auto", "text", "url", "email"], horizontal=True)
content = st.text_area("Content", height=220, max_chars=200_000)
uploaded = st.file_uploader("…or upload an .eml file", type=["eml"])

if st.button("Scan", type="primary") and (content.strip() or uploaded):
    headers = {"x-api-key": API_KEY} if API_KEY else {}
    try:
        if uploaded:
            r = requests.post(f"{API}/v1/scan/email/upload", files={"file": (uploaded.name, uploaded.getvalue())},
                              headers=headers, timeout=30)
        else:
            r = requests.post(f"{API}/v1/scan", json={"content": content, "input_type": mode}, headers=headers, timeout=30)
        r.raise_for_status()
    except requests.RequestException as exc:
        st.error(f"API error: {type(exc).__name__}")
        st.stop()
    res = r.json()
    st.subheader(f"{BADGE[res['label']]} · risk {res['risk_score']}/100")
    st.progress(res["risk_score"] / 100)
    st.text(f"Confidence: {res['confidence']:.2f} ({res['confidence_level']}) · input: {res['input_type']}")
    st.text(res["explanation"])
    st.info(res["recommended_action"])
    if res["red_flags"]:
        st.markdown("**Red flags**")
        for f in res["red_flags"]:
            st.text(f"[{f['severity']}] {f['description']}\n    evidence: {f['evidence']}  (+{f['contribution']:.2f})")
    if res["mitigating_factors"]:
        st.markdown("**Mitigating factors**")
        for f in res["mitigating_factors"]:
            st.text(f"{f['description']}  ({f['contribution']:.2f})")
    with st.expander("Layer scores, URLs and raw response"):
        st.json(res)
    with st.expander("Was this verdict wrong?"):
        correct = st.selectbox("Correct label", ["safe", "suspicious", "phishing", "scam"])
        if st.button("Send feedback"):
            requests.post(f"{API}/v1/feedback", json={"scan_id": res["scan_id"], "correct_label": correct},
                          headers=headers, timeout=10)
            st.success("Thanks - only the detection features are stored, not your message.")
