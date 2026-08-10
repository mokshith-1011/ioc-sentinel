import streamlit as st
from ioc import detect_ioc_type
from services.virustotal import lookup_virustotal
from services.abuseipdb import lookup_abuseipdb

st.set_page_config(page_title="IOC Checker", page_icon="🛡️", layout="wide")

st.title("🛡️ IOC Checker")
st.caption("Threat-intelligence enrichment tool for SOC investigations")

with st.sidebar:
    st.header("Settings")
    vt_key = st.text_input("VirusTotal API key", type="password")
    abuse_key = st.text_input("AbuseIPDB API key", type="password")
    st.info("Keys are used only for the current session and are not written to disk.")

ioc = st.text_input(
    "Enter an IOC",
    placeholder="Example: 8.8.8.8, example.com, https://example.com/login, or a SHA-256 hash"
)

col1, col2 = st.columns([1, 4])
with col1:
    check = st.button("🔎 Check IOC", type="primary", use_container_width=True)

if check:
    value = ioc.strip()
    if not value:
        st.warning("Enter an IOC first.")
        st.stop()

    ioc_type = detect_ioc_type(value)

    if ioc_type == "unknown":
        st.error("Could not confidently identify this IOC. Try an IP, domain, URL, or MD5/SHA1/SHA256 hash.")
        st.stop()

    st.subheader("IOC Classification")
    a, b, c = st.columns(3)
    a.metric("Type", ioc_type.upper())
    b.metric("Indicator", value[:45] + ("..." if len(value) > 45 else ""))
    c.metric("Status", "Ready for enrichment")

    vt_result = lookup_virustotal(value, ioc_type, vt_key) if vt_key else {
        "status": "not_configured",
        "message": "VirusTotal key not provided."
    }

    abuse_result = (
        lookup_abuseipdb(value, abuse_key)
        if abuse_key and ioc_type == "ip"
        else {"status": "not_applicable", "message": "AbuseIPDB enrichment is available for IP addresses."}
    )

    st.subheader("Threat Intelligence")

    left, right = st.columns(2)

    with left:
        st.markdown("### VirusTotal")
        if vt_result["status"] == "ok":
            data = vt_result["data"]
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            x1, x2, x3, x4 = st.columns(4)
            x1.metric("Malicious", malicious)
            x2.metric("Suspicious", suspicious)
            x3.metric("Harmless", harmless)
            x4.metric("Undetected", undetected)

            st.write("**Reputation:**", attrs.get("reputation", "N/A"))
            if attrs.get("country"):
                st.write("**Country:**", attrs.get("country"))
            if attrs.get("as_owner"):
                st.write("**ASN Owner:**", attrs.get("as_owner"))

            with st.expander("Raw VirusTotal response"):
                st.json(data)
        else:
            st.info(vt_result["message"])

    with right:
        st.markdown("### AbuseIPDB")
        if abuse_result["status"] == "ok":
            data = abuse_result["data"]
            x1, x2 = st.columns(2)
            x1.metric("Abuse Confidence", f'{data.get("abuseConfidenceScore", "N/A")}%')
            x2.metric("Reports", data.get("totalReports", "N/A"))
            st.write("**Country:**", data.get("countryCode", "N/A"))
            st.write("**ISP:**", data.get("isp", "N/A"))
            st.write("**Domain:**", data.get("domain", "N/A"))
            with st.expander("Raw AbuseIPDB response"):
                st.json(data)
        else:
            st.info(abuse_result["message"])

    st.subheader("SOC Analyst Assessment")

    malicious = 0
    suspicious = 0
    abuse_score = 0

    if vt_result["status"] == "ok":
        stats = vt_result["data"].get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)

    if abuse_result["status"] == "ok":
        abuse_score = int(abuse_result["data"].get("abuseConfidenceScore", 0) or 0)

    if malicious > 0 or abuse_score >= 75:
        verdict = "HIGH RISK"
    elif suspicious > 0 or abuse_score >= 25:
        verdict = "MEDIUM RISK"
    else:
        verdict = "LOW / NO EVIDENCE"

    st.warning(f"Assessment: **{verdict}**")
    st.caption(
        "This assessment is a simple project heuristic, not a definitive malware verdict. "
        "Analysts should validate context, timestamps, asset criticality, and additional telemetry."
    )
