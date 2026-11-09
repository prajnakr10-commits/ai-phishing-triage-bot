"""Run with: streamlit run app.py"""
import json
import streamlit as st
from triage.analyzer import analyze_email
from triage.ai import explain_locally
from triage.virustotal import lookup_url

st.set_page_config(page_title='AI Phishing Triage Bot', page_icon='🛡️', layout='wide')
st.title('🛡️ AI-Assisted Phishing Triage Bot')
st.caption('Educational SOC L1 project • static inspection • no URL visits or attachment execution')
st.info('Upload only synthetic or authorized emails. The app runs locally and does not save uploaded email files.')
up = st.file_uploader('Upload an .eml email file (maximum 10 MB)', type=['eml'])
if up:
    try:
        report = analyze_email(up.getvalue())
    except Exception as exc:
        st.error(f'Email could not be analyzed: {exc}')
        st.stop()
    c1, c2, c3 = st.columns(3)
    c1.metric('Risk score (heuristic)', f"{report['score']}/100")
    c2.metric('Priority', report['classification'])
    c3.metric('Indicators', len(report['indicators']))
    st.subheader('Message metadata')
    st.write({'Subject': report['subject'], 'From': report['sender'], 'Reply-To': report['reply_to'],
              'Date': report['date'], 'Email SHA-256': report['sha256_email']})
    st.subheader('Authentication Results (as reported in header)')
    st.json(report['authentication'])
    st.caption('Header results are unverified claims in this standalone file; check trusted mail-server context before relying on them.')
    st.subheader('Indicators and recommendations')
    st.dataframe(report['indicators'], use_container_width=True)
    st.write(report['recommendation'])
    with st.expander('Extracted URLs — do not open unless validated in a safe environment'):
        st.code('\n'.join(report['urls']) or '(none)')
    with st.expander('Attachment metadata and hashes'):
        st.json(report['attachments'])
    with st.expander('Short message preview (plain text)'):
        st.text(report['body_preview'])
    st.download_button('Download triage report (JSON)', json.dumps(report, indent=2),
                       file_name='phishing_triage_report.json', mime='application/json')
    
    # Optional VirusTotal threat intelligence
    st.subheader("VirusTotal Threat Intelligence")
    st.caption(
        "Manual, read-only reputation lookup. "
        "Only check public or authorized, non-sensitive URLs."
    )

    if report["urls"]:
        selected_url = st.selectbox(
            "Select a URL to investigate",
            report["urls"],
            key="vt_selected_url"
        )

        if st.button("Check VirusTotal Reputation"):
            api_key = st.secrets.get("VT_API_KEY", "")

            if not api_key:
                st.error("VirusTotal API key is not configured.")
            else:
                with st.spinner("Checking existing VirusTotal report..."):
                    vt_result = lookup_url(selected_url, api_key)

                if vt_result["status"] == "success":
                    st.success("VirusTotal report retrieved.")

                    c1, c2, c3, c4 = st.columns(4)
                    c1.metric("Malicious", vt_result["malicious"])
                    c2.metric("Suspicious", vt_result["suspicious"])
                    c3.metric("Harmless", vt_result["harmless"])
                    c4.metric("Undetected", vt_result["undetected"])

                    st.caption(
                        "Vendor detections are supporting evidence, "
                        "not a definitive phishing verdict."
                    )
                elif vt_result["status"] == "not_found":
                    st.warning(
                        "No existing VirusTotal report was found."
                    )
                else:
                    st.error(
                        vt_result.get(
                            "message",
                            "VirusTotal lookup unavailable."
                        )
                    )
    else:
        st.info("No URLs were extracted from this email.")

    st.divider()
    st.subheader('Optional local AI explanation')
    st.caption('Requires Ollama running locally with llama3.2; score is not AI-generated.')
    if st.button('Generate AI explanation'):
        with st.spinner('Querying local AI model...'):
            st.write(explain_locally(report))
else:
    st.write('Try one of the included sample .eml files from the samples folder.')
