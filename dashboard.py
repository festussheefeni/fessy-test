"""
RansomGuard decision-support dashboard (Streamlit prototype).

Run with:  streamlit run dashboard.py
Loads pre-computed outputs from ../outputs and ../data. Re-run the src/
pipeline scripts (data_gen -> eda -> supervised_model -> unsupervised_model
-> incident_correlation -> nlp_pipeline -> simulation -> risk_score ->
threat_intel) before launching if you want fresh numbers.
"""
import json
import os

import pandas as pd
import streamlit as st
import plotly.express as px

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(BASE, "data")
OUT = os.path.join(BASE, "outputs")

st.set_page_config(page_title="RansomGuard — Hospital Ransomware Early Warning", layout="wide")


@st.cache_data
def load_json(name):
    with open(os.path.join(OUT, name)) as f:
        return json.load(f)


@st.cache_data
def load_csv(name):
    return pd.read_csv(os.path.join(OUT, name))


st.title("🛡️ RansomGuard — Early-Warning Analytics & Recovery Prioritisation")
st.caption("SAS821S Capstone · T04 Healthcare Ransomware Early Warning and Clinical-System Resilience")

tabs = st.tabs(["Overview", "Supervised ML", "Anomaly Detection (UBA)", "Incident Timeline",
                 "Security Intelligence", "Simulation", "Text Mining / NLP", "Risk Score & Alerts"])

# ---------------------------------------------------------------------------
with tabs[0]:
    st.subheader("Executive risk overview")
    try:
        intel = load_json("threat_intelligence_report.json")
        kn = intel["executive_product"]["key_numbers"]
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Affected user accounts", kn["affected_user_accounts"])
        c2.metric("Affected hosts", kn["affected_hosts"])
        c3.metric("Alert threshold (risk score)", kn["risk_alert_threshold"])
        c4.metric("Downtime avoided (hrs, combined controls)", kn["downtime_reduction_hours_with_combined_controls"])
        st.info(intel["executive_product"]["headline"])
        st.success(intel["executive_product"]["recommendation"])
    except FileNotFoundError:
        st.warning("Run the analytics pipeline (src/*.py) first to populate this dashboard.")

# ---------------------------------------------------------------------------
with tabs[1]:
    st.subheader("Supervised classification — phishing & malicious endpoint activity")
    try:
        sup = load_json("supervised_model_results.json")
        col1, col2 = st.columns(2)
        for col, task in zip([col1, col2], sup.keys()):
            with col:
                st.markdown(f"**{task}**")
                m = sup[task]["xgboost"]
                st.write(f"Accuracy: {m['accuracy']} · Precision: {m['precision']} · "
                         f"Recall: {m['recall']} · **F1: {m['f1_score']}** · ROC-AUC: {m['roc_auc']}")
                cm = m["confusion_matrix"]
                cm_df = pd.DataFrame(cm, index=["actual 0", "actual 1"], columns=["pred 0", "pred 1"])
                st.dataframe(cm_df)
                if "top_features" in m:
                    fi = pd.DataFrame(m["top_features"])
                    fig = px.bar(fi, x="importance", y="feature", orientation="h", title="Top features (XGBoost)")
                    st.plotly_chart(fig, use_container_width=True)
    except FileNotFoundError:
        st.warning("Run src/supervised_model.py first.")

# ---------------------------------------------------------------------------
with tabs[2]:
    st.subheader("Unsupervised behavioural anomaly detection")
    try:
        unsup = load_json("unsupervised_model_results.json")
        c1, c2 = st.columns(2)
        c1.json(unsup["user_isolation_forest"])
        c2.json(unsup["host_dbscan"])
        top_users = load_csv("top_anomalous_users.csv")
        st.markdown("**Top anomalous users (Isolation Forest)**")
        st.dataframe(top_users)
    except FileNotFoundError:
        st.warning("Run src/unsupervised_model.py first.")

# ---------------------------------------------------------------------------
with tabs[3]:
    st.subheader("Correlated incident timeline")
    try:
        timeline = load_csv("incident_timeline.csv")
        entity_filter = st.multiselect("Filter by source", timeline.source.unique().tolist(),
                                        default=timeline.source.unique().tolist())
        filtered = timeline[timeline.source.isin(entity_filter)]
        st.dataframe(filtered.sort_values("timestamp"), height=420)
        fig = px.scatter(filtered, x="timestamp", y="mitre_phase", color="source",
                          hover_data=["entity", "event"], title="Correlated events by MITRE phase over time")
        st.plotly_chart(fig, use_container_width=True)
    except FileNotFoundError:
        st.warning("Run src/incident_correlation.py first.")

# ---------------------------------------------------------------------------
with tabs[4]:
    st.subheader("Security intelligence: IOCs, MITRE mapping & executive briefing")
    try:
        intel = load_json("threat_intelligence_report.json")
        st.markdown("**Priority intelligence requirements**")
        for q in intel["priority_intelligence_requirements"]:
            st.markdown(f"- {q}")
        c1, c2 = st.columns(2)
        c1.markdown("**Malicious sender domains**")
        c1.dataframe(pd.DataFrame(intel["indicators_of_compromise"]["malicious_sender_domains"]))
        c2.markdown("**Malicious process names**")
        c2.dataframe(pd.DataFrame(intel["indicators_of_compromise"]["malicious_process_names"]))
        st.markdown("**MITRE ATT&CK mapping**")
        st.dataframe(pd.DataFrame(intel["mitre_attack_mapping"]).T)
    except FileNotFoundError:
        st.warning("Run src/threat_intel.py first.")

# ---------------------------------------------------------------------------
with tabs[5]:
    st.subheader("Ransomware propagation simulation — control-scenario comparison")
    try:
        sim = load_json("simulation_results.json")
        sim_df = pd.DataFrame(sim).T.reset_index().rename(columns={"index": "scenario"})
        st.dataframe(sim_df)
        fig = px.bar(sim_df, x="scenario", y="mean_pct_infected", error_y="std_pct_infected",
                     title="Mean % hosts infected by control scenario (200 Monte-Carlo runs)")
        st.plotly_chart(fig, use_container_width=True)
        fig2 = px.bar(sim_df, x="scenario", y="mean_downtime_hours",
                      title="Mean estimated clinical-system downtime (hours)")
        st.plotly_chart(fig2, use_container_width=True)
    except FileNotFoundError:
        st.warning("Run src/simulation.py first.")

# ---------------------------------------------------------------------------
with tabs[6]:
    st.subheader("Text mining / NLP — SOC tickets & threat-intel narratives")
    try:
        nlp = load_json("nlp_results.json")
        st.write(f"Classification (ransomware-relevant vs not): "
                 f"Accuracy {nlp['classification']['accuracy']}, F1 {nlp['classification']['f1_score']}")
        c1, c2 = st.columns(2)
        c1.markdown("**Top ransomware-relevant terms**")
        c1.write(", ".join(nlp["classification"]["top_ransomware_relevant_terms"]))
        c2.markdown("**Top benign terms**")
        c2.write(", ".join(nlp["classification"]["top_benign_terms"]))
        st.markdown("**NMF topics**")
        for t in nlp["topics"]:
            st.markdown(f"- Topic {t['topic_id']}: {', '.join(t['top_terms'])}")
    except FileNotFoundError:
        st.warning("Run src/nlp_pipeline.py first.")

# ---------------------------------------------------------------------------
with tabs[7]:
    st.subheader("Early-warning risk score & adversarial robustness")
    try:
        risk = load_json("risk_score_results.json")
        st.json(risk["threshold_selection"])
        st.markdown("**Adversarial / drift robustness**")
        st.dataframe(pd.DataFrame(risk["adversarial_robustness"]).T)
        host_risk = load_csv("host_day_risk_scores.csv")
        st.markdown("**Highest-risk host-days**")
        st.dataframe(host_risk.sort_values("risk_score", ascending=False).head(20))
    except FileNotFoundError:
        st.warning("Run src/risk_score.py first.")

st.sidebar.title("RansomGuard")
st.sidebar.markdown("Early-warning analytics and recovery prioritisation for hospital networks.")
st.sidebar.markdown("Synthetic data only — no real patient or hospital data is used.")
