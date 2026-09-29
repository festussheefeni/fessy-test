"""
Incident investigation: correlate flagged events across email, endpoint,
identity/network/backup and text sources into a single chronological
incident timeline, keyed on shared user/host entities.
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
identity = read_csv_ts(f"{DATA}/identity_network_backup_logs.csv")
text = read_csv_ts(f"{DATA}/text_soc_threatintel.csv")

with open(f"{DATA}/campaign_ground_truth.json") as f:
    campaign = json.load(f)
suspect_users = set(campaign["compromised_users"] + campaign["attacker_admin_targets"])
suspect_hosts = set(campaign["compromised_hosts"])

events = []

for _, r in email[email.label_phishing == 1].iterrows():
    if r.recipient_user_id in suspect_users:
        events.append({"timestamp": r.timestamp, "source": "email_gateway", "entity_type": "user",
                        "entity": r.recipient_user_id, "event": "phishing_email_delivered",
                        "detail": f"sender_domain={r.sender_domain}, spf={r.spf_result}, dkim={r.dkim_result}"})

for _, r in endpoint[endpoint.label_malicious == 1].iterrows():
    if r.host_id in suspect_hosts:
        ev = "shadow_copy_deletion" if r.shadow_copy_deletion else \
             ("file_encryption_indicator" if r.file_encryption_indicator else "suspicious_process_execution")
        events.append({"timestamp": r.timestamp, "source": "endpoint_edr", "entity_type": "host",
                        "entity": r.host_id, "event": ev,
                        "detail": f"process={r.process_name}, parent={r.parent_process}, registry_change={bool(r.registry_change)}"})

id_susp = identity[identity.label_suspicious == 1]
for _, r in id_susp.iterrows():
    if r.backup_job_status in ("deleted", "failed", "disabled"):
        ev = "backup_tampering"
    elif r.mfa_status in ("bypassed", "not_used") and r.privilege_level in ("admin", "domain_admin"):
        ev = "privileged_logon_without_mfa"
    elif r.off_hours_logon:
        ev = "off_hours_anomalous_logon"
    else:
        ev = "suspicious_authentication_event"
    events.append({"timestamp": r.timestamp, "source": "identity_network_backup", "entity_type": "user",
                    "entity": r.user_id, "event": ev,
                    "detail": f"dst={r.destination_host}, auth={r.authentication_result}, mfa={r.mfa_status}, priv={r.privilege_level}"})

for _, r in text[text.is_ransomware_relevant == 1].iterrows():
    events.append({"timestamp": r.timestamp, "source": "soc_text_intel", "entity_type": "mixed",
                    "entity": f"user:{r.related_user}|host:{r.related_host}", "event": f"text_report:{r.category_label}",
                    "detail": r.text_content})

timeline = pd.DataFrame(events).sort_values("timestamp").reset_index(drop=True)
timeline.to_csv(f"{OUT}/incident_timeline.csv", index=False)

# Attack-phase summary counts, mapped loosely to MITRE ATT&CK tactics
phase_map = {
    "phishing_email_delivered": "Initial Access (TA0001)",
    "off_hours_anomalous_logon": "Credential Access / Lateral Movement (TA0006/TA0008)",
    "privileged_logon_without_mfa": "Privilege Escalation (TA0004)",
    "suspicious_authentication_event": "Credential Access (TA0006)",
    "suspicious_process_execution": "Execution / Defense Evasion (TA0002/TA0005)",
    "backup_tampering": "Impact — Inhibit System Recovery (TA0040/T1490)",
    "file_encryption_indicator": "Impact — Data Encrypted for Impact (T1486)",
    "shadow_copy_deletion": "Impact — Inhibit System Recovery (T1490)",
}
timeline["mitre_phase"] = timeline.event.map(lambda e: phase_map.get(e, "Security Intelligence Report" if str(e).startswith("text_report") else "Other"))

phase_summary = timeline.groupby("mitre_phase").size().sort_values(ascending=False)
affected_users = sorted(timeline[timeline.entity_type == "user"].entity.unique().tolist())
affected_hosts = sorted(timeline[timeline.entity_type == "host"].entity.unique().tolist())

summary = {
    "total_correlated_events": int(len(timeline)),
    "date_range": [str(timeline.timestamp.min()), str(timeline.timestamp.max())],
    "affected_users": affected_users,
    "affected_hosts": affected_hosts,
    "phase_summary": phase_summary.to_dict(),
    "first_indicator": timeline.iloc[0][["timestamp", "source", "event", "entity"]].to_dict(),
    "last_indicator": timeline.iloc[-1][["timestamp", "source", "event", "entity"]].to_dict(),
}
with open(f"{OUT}/incident_summary.json", "w") as f:
    json.dump(summary, f, indent=2, default=str)

print(json.dumps(summary, indent=2, default=str))
print(f"\nTimeline rows: {len(timeline)} -> {OUT}/incident_timeline.csv")
