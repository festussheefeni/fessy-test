"""
Security intelligence: consolidate IOC-style indicators from email, text and
endpoint sources, map to MITRE ATT&CK techniques, and produce an operational
IOC summary plus an executive-readable risk briefing.
"""
import json
import sys
sys.path.insert(0, "/home/claude/ransomguard/src")
from util import read_csv_ts

import pandas as pd

DATA = "/home/claude/ransomguard/data"
OUT = "/home/claude/ransomguard/outputs"

email = read_csv_ts(f"{DATA}/email_gateway_logs.csv")
endpoint = read_csv_ts(f"{DATA}/endpoint_edr_logs.csv")
with open(f"{OUT}/incident_summary.json") as f:
    incident_summary = json.load(f)
with open(f"{OUT}/simulation_results.json") as f:
    sim = json.load(f)
with open(f"{OUT}/risk_score_results.json") as f:
    risk = json.load(f)

# IOC extraction (domains, process hashes tied to confirmed-malicious activity)
malicious_domains = sorted(email.loc[email.label_phishing == 1, "sender_domain"].value_counts().head(10).to_dict().items(),
                            key=lambda x: -x[1])
malicious_processes = sorted(endpoint.loc[endpoint.label_malicious == 1, "process_name"].value_counts().to_dict().items(),
                              key=lambda x: -x[1])

MITRE_MAP = {
    "phishing_email_delivered": {"tactic": "Initial Access", "technique": "T1566 Phishing"},
    "off_hours_anomalous_logon": {"tactic": "Lateral Movement", "technique": "T1021 Remote Services"},
    "privileged_logon_without_mfa": {"tactic": "Privilege Escalation", "technique": "T1078 Valid Accounts"},
    "suspicious_authentication_event": {"tactic": "Credential Access", "technique": "T1110 Brute Force / T1556 MFA Interference"},
    "suspicious_process_execution": {"tactic": "Execution", "technique": "T1059 Command and Scripting Interpreter"},
    "backup_tampering": {"tactic": "Impact", "technique": "T1490 Inhibit System Recovery"},
    "file_encryption_indicator": {"tactic": "Impact", "technique": "T1486 Data Encrypted for Impact"},
    "shadow_copy_deletion": {"tactic": "Impact", "technique": "T1490 Inhibit System Recovery"},
}

ioc_summary = {
    "priority_intelligence_requirements": [
        "Are hospital users receiving phishing lures from known malicious sending domains?",
        "Is any endpoint executing living-off-the-land binaries consistent with ransomware staging?",
        "Are backup jobs being disabled or shadow copies deleted outside change-control windows?",
        "Which accounts show privileged, MFA-bypassed, off-hours logons?",
    ],
    "collection_sources": ["email_gateway_logs", "endpoint_edr_logs", "identity_network_backup_logs",
                            "text_soc_threatintel (SOC tickets + public threat-intel narratives)"],
    "indicators_of_compromise": {
        "malicious_sender_domains": [{"domain": d, "occurrences": int(c)} for d, c in malicious_domains],
        "malicious_process_names": [{"process": p, "occurrences": int(c)} for p, c in malicious_processes],
    },
    "mitre_attack_mapping": MITRE_MAP,
    "analysis_and_confidence": {
        "confidence_level": "High",
        "rationale": ("Corroborated across four independent telemetry sources (email, endpoint, identity, "
                      "text/SOC) with a consistent MITRE ATT&CK kill-chain progression from Initial Access "
                      "through to Impact, affecting "
                      f"{len(incident_summary['affected_users'])} user accounts and "
                      f"{len(incident_summary['affected_hosts'])} hosts."),
    },
    "operational_product": {
        "description": "Analyst-facing IOC watchlist and MITRE-tagged incident timeline for SOC triage.",
        "artefact": "outputs/incident_timeline.csv (mitre_phase column), outputs/host_day_risk_scores.csv",
    },
    "executive_product": {
        "headline": "Hospital network shows corroborated ransomware precursor activity across email, endpoint and identity telemetry.",
        "key_numbers": {
            "affected_user_accounts": len(incident_summary["affected_users"]),
            "affected_hosts": len(incident_summary["affected_hosts"]),
            "risk_alert_threshold": risk["threshold_selection"]["alert_threshold_risk_score"],
            "baseline_scenario_mean_pct_infected": sim["baseline_no_controls"]["mean_pct_infected"],
            "combined_controls_mean_pct_infected": sim["segmentation_plus_early_edr"]["mean_pct_infected"],
            "downtime_reduction_hours_with_combined_controls": round(
                sim["baseline_no_controls"]["mean_downtime_hours"] - sim["segmentation_plus_early_edr"]["mean_downtime_hours"], 1),
        },
        "recommendation": ("Activate network segmentation and enable automatic EDR host isolation at the "
                            "validated risk-score alert threshold; simulation shows this combination reduces "
                            "mean projected infection spread from "
                            f"{sim['baseline_no_controls']['mean_pct_infected']}% to "
                            f"{sim['segmentation_plus_early_edr']['mean_pct_infected']}% of hosts."),
    },
    "feedback_loop": ("Weekly SOC review of false-positive/negative alerts feeds back into risk-score "
                       "recalibration (see risk_score_results.json governance_note) and IOC list pruning."),
}

with open(f"{OUT}/threat_intelligence_report.json", "w") as f:
    json.dump(ioc_summary, f, indent=2)

print(json.dumps(ioc_summary, indent=2))
