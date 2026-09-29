"""
RansomGuard - synthetic hospital-network security dataset generator.

Generates five interlinked, labelled datasets representing 30 days of a
simulated hospital network with an embedded ransomware precursor campaign
(phishing -> credential compromise -> lateral movement -> backup tampering
-> pre-encryption staging). All data is synthetic; no real identities,
PHI or infrastructure are used.
"""
import hashlib
import json
import random
from datetime import datetime, timedelta

import numpy as np
import pandas as pd

RNG_SEED = 42
random.seed(RNG_SEED)
np.random.seed(RNG_SEED)

START = datetime(2026, 8, 11)          # matches charter work-plan Task 1 start
DAYS = 30
N_USERS = 150
N_HOSTS = 80
OUT = "/home/claude/ransomguard/data"

DEPARTMENTS = ["Radiology", "EHR-Admin", "Laboratory", "Pharmacy", "Finance",
               "IT-Ops", "Nursing", "Executive", "HR", "Facilities"]
PRIV_LEVELS = ["standard", "power_user", "admin", "domain_admin"]
PRIV_WEIGHTS = [0.70, 0.18, 0.10, 0.02]


def h(s):
    return hashlib.sha256(str(s).encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Entities
# ---------------------------------------------------------------------------
users = []
for i in range(N_USERS):
    uid = f"U{1000+i}"
    dept = random.choice(DEPARTMENTS)
    priv = random.choices(PRIV_LEVELS, weights=PRIV_WEIGHTS)[0]
    if dept == "IT-Ops":
        priv = random.choices(["power_user", "admin", "domain_admin"], weights=[0.3, 0.5, 0.2])[0]
    users.append({"user_id": uid, "department": dept, "privilege_level": priv,
                  "user_id_hash": h(uid)})
users_df = pd.DataFrame(users)

hosts = []
for i in range(N_HOSTS):
    hid = f"HOST-{2000+i}"
    dept = random.choice(DEPARTMENTS)
    role = random.choice(["workstation", "workstation", "workstation",
                           "clinical_app_server", "file_server", "backup_server", "domain_controller"])
    hosts.append({"host_id": hid, "department": dept, "role": role,
                   "private_ip": f"10.{random.randint(1,20)}.{random.randint(0,254)}.{random.randint(2,254)}"})
hosts_df = pd.DataFrame(hosts)
backup_hosts = hosts_df[hosts_df.role == "backup_server"].host_id.tolist()
dc_hosts = hosts_df[hosts_df.role == "domain_controller"].host_id.tolist()

# ---------------------------------------------------------------------------
# Attack campaign scenario (ground truth, kept for evaluation only)
# ---------------------------------------------------------------------------
CAMPAIGN_START_DAY = 20     # phishing wave
CAMPAIGN_LATERAL_DAY = 23   # credential misuse / lateral movement
CAMPAIGN_BACKUP_DAY = 26    # backup tampering
CAMPAIGN_STAGE_DAY = 28     # pre-encryption staging / mass file ops

compromised_users = list(np.random.choice(
    users_df[users_df.department != "Executive"].user_id, size=12, replace=False))
attacker_admin_targets = list(users_df[users_df.privilege_level.isin(["admin", "domain_admin"])]
                               .user_id.sample(4, random_state=RNG_SEED))
compromised_hosts = list(np.random.choice(hosts_df.host_id, size=15, replace=False))
staging_host = compromised_hosts[0]

campaign_meta = {
    "compromised_users": compromised_users,
    "attacker_admin_targets": attacker_admin_targets,
    "compromised_hosts": compromised_hosts,
    "staging_host": staging_host,
    "backup_hosts_targeted": backup_hosts[:2],
    "timeline": {
        "phishing_wave": (START + timedelta(days=CAMPAIGN_START_DAY)).isoformat(),
        "lateral_movement": (START + timedelta(days=CAMPAIGN_LATERAL_DAY)).isoformat(),
        "backup_tampering": (START + timedelta(days=CAMPAIGN_BACKUP_DAY)).isoformat(),
        "encryption_staging": (START + timedelta(days=CAMPAIGN_STAGE_DAY)).isoformat(),
    },
}
with open(f"{OUT}/campaign_ground_truth.json", "w") as f:
    json.dump(campaign_meta, f, indent=2)


def rand_ts(day_offset, hour_low=6, hour_high=22):
    d = START + timedelta(days=int(day_offset))
    return d + timedelta(hours=random.uniform(hour_low, hour_high))


# ---------------------------------------------------------------------------
# 1. Email gateway logs (~1500) — phishing / benign classification target
# ---------------------------------------------------------------------------
PHISH_SUBJECTS = [
    "Urgent: Password expires today - verify now",
    "Invoice overdue - action required",
    "IT Security: mailbox quota exceeded",
    "Payroll update - confirm your details",
    "Shared document requires your signature",
    "Patient records access alert - verify identity",
    "VPN certificate renewal required immediately",
    "Your account has been locked - click to restore",
]
BENIGN_SUBJECTS = [
    "Weekly clinical roster",
    "Meeting notes - department sync",
    "Lab results batch export",
    "Facilities maintenance schedule",
    "Reminder: annual compliance training",
    "Radiology equipment calibration",
    "Staff newsletter - August",
    "Shift handover summary",
]
EXTERNAL_DOMAINS = ["secure-mail-verify.com", "healthportal-update.net", "docu-sign-alert.com",
                     "it-support-helpdesk.info", "payroll-confirm.biz"]

LEGIT_EXTERNAL_DOMAINS = ["medsupply-partners.com", "radiology-cloud-pacs.net", "payroll-provider.co.za"]

rows = []
n_email = 1500
n_phish = int(n_email * 0.30)
for i in range(n_email):
    is_phish = i < n_phish
    day = np.random.randint(0, DAYS)
    # concentrate a phishing wave in the campaign window for the compromised users
    if is_phish and random.random() < 0.4:
        day = CAMPAIGN_START_DAY + random.randint(0, 2)
        recipient = random.choice(compromised_users)
    else:
        recipient = random.choice(users_df.user_id.tolist())
    ts = rand_ts(day)
    # class overlap / noise: ~12% of phishing spoofs an internal-looking domain,
    # ~10% of benign mail legitimately comes from an external partner domain
    if is_phish:
        sender_domain = "hospital-trust.local" if random.random() < 0.12 else random.choice(EXTERNAL_DOMAINS)
    else:
        sender_domain = random.choice(LEGIT_EXTERNAL_DOMAINS) if random.random() < 0.10 else "hospital-trust.local"
    subject = random.choice(PHISH_SUBJECTS) if is_phish else random.choice(BENIGN_SUBJECTS)
    # occasional subject-style overlap (urgent-but-legitimate ops mail; blandly worded phishing)
    if not is_phish and random.random() < 0.08:
        subject = random.choice(PHISH_SUBJECTS)
    if is_phish and random.random() < 0.10:
        subject = random.choice(BENIGN_SUBJECTS)
    has_url = (is_phish and random.random() < 0.80) or (not is_phish and random.random() < 0.06)
    spf = random.choice(["fail", "softfail"]) if is_phish and random.random() < 0.65 else "pass"
    if not is_phish and random.random() < 0.04:
        spf = "softfail"
    dkim = "fail" if is_phish and random.random() < 0.55 else "pass"
    dmarc = "fail" if (spf == "fail" or dkim == "fail") and random.random() < 0.7 else "pass"
    n_attachments = np.random.poisson(0.3 if not is_phish else 0.55)
    rows.append({
        "email_id": f"E{i:05d}",
        "timestamp": ts.isoformat(),
        "sender_hash": h(f"{sender_domain}-{i%50}"),
        "sender_domain": sender_domain,
        "recipient_hash": h(recipient),
        "recipient_user_id": recipient,  # kept for correlation; drop before modelling to avoid leakage of raw id
        "subject_length": len(subject),
        "subject_has_urgency_kw": int(any(k in subject.lower() for k in
                                           ["urgent", "immediately", "today", "alert", "required", "locked"])),
        "embedded_url_count": (np.random.poisson(1.6) + 1) if has_url else 0,
        "attachment_count": n_attachments,
        "attachment_hash": h(f"att-{i}") if n_attachments > 0 else "",
        "spf_result": spf,
        "dkim_result": dkim,
        "dmarc_result": dmarc,
        "sender_is_external": int(sender_domain != "hospital-trust.local"),
        "label_phishing": int(is_phish),
    })
email_df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
email_df.to_csv(f"{OUT}/email_gateway_logs.csv", index=False)

# ---------------------------------------------------------------------------
# 2. Endpoint / EDR telemetry (~2000 events)
# ---------------------------------------------------------------------------
BENIGN_PROCS = ["explorer.exe", "outlook.exe", "chrome.exe", "winword.exe",
                "backup_agent.exe", "emr_client.exe", "svchost.exe", "teams.exe"]
MALICIOUS_PROCS = ["powershell.exe", "rundll32.exe", "certutil.exe", "wscript.exe",
                    "psexec.exe", "vssadmin.exe", "cmd.exe"]

rows = []
n_endpoint = 2000
n_malicious = int(n_endpoint * 0.22)
for i in range(n_endpoint):
    is_malicious = i < n_malicious
    if is_malicious:
        day = np.random.choice(
            range(CAMPAIGN_LATERAL_DAY, CAMPAIGN_STAGE_DAY + 2),
            p=None)
        host = random.choice(compromised_hosts)
        parent = random.choice(["outlook.exe", "winword.exe", "explorer.exe"])
        # ~12% of malicious activity hides behind a normally-benign process name
        # (living-off-the-land / process-name spoofing) to avoid trivial separability
        proc = random.choice(BENIGN_PROCS) if random.random() < 0.12 else random.choice(MALICIOUS_PROCS)
        registry_change = int(random.random() < 0.55)
        file_enc_indicator = int(day >= CAMPAIGN_STAGE_DAY and random.random() < 0.6)
        file_delete_shadow = int(proc == "vssadmin.exe")
        bytes_written = int(np.random.lognormal(11, 1.4)) if file_enc_indicator else int(np.random.lognormal(6, 1))
    else:
        day = np.random.randint(0, DAYS)
        host = random.choice(hosts_df.host_id.tolist())
        parent = "explorer.exe"
        # IT-Ops legitimately runs admin tooling (powershell/cmd) ~9% of the time
        proc = random.choice(["powershell.exe", "cmd.exe"]) if random.random() < 0.09 else random.choice(BENIGN_PROCS)
        registry_change = int(random.random() < 0.06)
        file_enc_indicator = 0
        file_delete_shadow = 0
        bytes_written = int(np.random.lognormal(5, 1.1))
        # small chance of an elevated but still benign file-touch burst (patch/index job)
        if random.random() < 0.05:
            bytes_written = int(np.random.lognormal(9, 1))
    ts = rand_ts(day, 0, 23.9)
    rows.append({
        "event_id": f"EP{i:05d}",
        "timestamp": ts.isoformat(),
        "host_id": host,
        "parent_process": parent,
        "process_name": proc,
        "process_hash": h(f"{proc}-{i%40}"),
        "registry_change": registry_change,
        "file_create_mod_count": int(np.random.poisson(25 if file_enc_indicator else 2)),
        "file_encryption_indicator": file_enc_indicator,
        "shadow_copy_deletion": file_delete_shadow,
        "bytes_written": bytes_written,
        "label_malicious": int(is_malicious),
    })
endpoint_df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
endpoint_df.to_csv(f"{OUT}/endpoint_edr_logs.csv", index=False)

# ---------------------------------------------------------------------------
# 3. Identity, network & backup logs (~2500)
# ---------------------------------------------------------------------------
rows = []
n_id = 2500
n_anom = int(n_id * 0.15)
for i in range(n_id):
    is_anom = i < n_anom
    if is_anom:
        day = np.random.choice(range(CAMPAIGN_LATERAL_DAY, CAMPAIGN_STAGE_DAY + 2))
        user = random.choice(compromised_users + attacker_admin_targets)
        hour = random.choice([1, 2, 3, 4, 23])       # off-hours logons
        ts = (START + timedelta(days=int(day))) + timedelta(hours=hour, minutes=random.randint(0, 59))
        src_ip = f"10.{random.randint(1,20)}.{random.randint(0,254)}.{random.randint(2,254)}"
        auth_result = random.choices(["success", "failure"], weights=[0.6, 0.4])[0]
        mfa = random.choices(["not_used", "bypassed", "used"], weights=[0.5, 0.3, 0.2])[0]
        priv = random.choice(["admin", "domain_admin"])
        dst_host = random.choice(compromised_hosts + dc_hosts)
        traffic_vol = int(np.random.lognormal(9, 1.2))
        backup_job = random.choices(["deleted", "failed", "disabled"], weights=[0.3, 0.4, 0.3])[0] \
            if dst_host in backup_hosts and day >= CAMPAIGN_BACKUP_DAY else \
            random.choices(["success", "failed"], weights=[0.9, 0.1])[0]
        ports = random.choice([3389, 445, 5985, 22])
    else:
        day = np.random.randint(0, DAYS)
        hour = random.uniform(7, 19)
        ts = (START + timedelta(days=int(day))) + timedelta(hours=hour)
        user = random.choice(users_df.user_id.tolist())
        src_ip = f"10.{random.randint(1,20)}.{random.randint(0,254)}.{random.randint(2,254)}"
        auth_result = random.choices(["success", "failure"], weights=[0.95, 0.05])[0]
        mfa = random.choices(["used", "not_used"], weights=[0.85, 0.15])[0]
        row_user = users_df[users_df.user_id == user].iloc[0]
        priv = row_user.privilege_level
        dst_host = random.choice(hosts_df.host_id.tolist())
        traffic_vol = int(np.random.lognormal(6, 0.8))
        backup_job = random.choices(["success", "failed"], weights=[0.97, 0.03])[0]
        ports = random.choice([443, 80, 3389, 445])
    rows.append({
        "record_id": f"ID{i:05d}",
        "timestamp": ts.isoformat(),
        "user_id": user,
        "user_id_hash": h(user),
        "source_ip": src_ip,
        "destination_host": dst_host,
        "port": ports,
        "authentication_result": auth_result,
        "mfa_status": mfa,
        "privilege_level": priv,
        "traffic_volume_bytes": traffic_vol,
        "backup_job_status": backup_job,
        "off_hours_logon": int(not (7 <= ts.hour <= 19)),
        "label_suspicious": int(is_anom),
    })
identity_df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
identity_df.to_csv(f"{OUT}/identity_network_backup_logs.csv", index=False)

# ---------------------------------------------------------------------------
# 4. Text data source: SOC tickets, phishing email bodies, threat-intel notes (~300)
# ---------------------------------------------------------------------------
SOC_TEMPLATES = [
    ("SOC_TICKET", "benign", "User {u} reported a slow VPN connection from {ip}; resolved by restarting client."),
    ("SOC_TICKET", "benign", "Scheduled patch deployment completed on {host} with no errors."),
    ("SOC_TICKET", "benign", "Password reset requested by {u} via self-service portal, verified via helpdesk callback."),
    ("SOC_TICKET", "phishing_report", "User {u} reported a suspicious email referencing account verification from an external domain."),
    ("SOC_TICKET", "malware_alert", "EDR flagged {proc} spawned from Outlook on {host}; process attempted registry modification."),
    ("SOC_TICKET", "credential_compromise", "Multiple failed logons followed by a successful off-hours logon for {u} from unrecognised IP {ip}."),
    ("SOC_TICKET", "backup_tampering", "Backup job on {host} was disabled outside change-control window; VSS shadow copies also deleted."),
    ("SOC_TICKET", "ransomware_precursor", "High-volume file modification and encryption-pattern indicators detected on {host}, consistent with pre-encryption staging."),
    ("THREAT_INTEL", "ioc_report", "Threat intelligence indicates phishing domains such as secure-mail-verify.com are associated with a known ransomware affiliate using {proc} for lateral movement."),
    ("PHISHING_EMAIL", "phishing_body", "Dear {u}, your mailbox quota has been exceeded. Verify your credentials immediately to avoid account suspension."),
]
rows = []
n_text = 300
for i in range(n_text):
    src_type, category, tmpl = random.choice(SOC_TEMPLATES)
    day = CAMPAIGN_START_DAY + random.randint(-15, 12) if category != "benign" else np.random.randint(0, DAYS)
    day = max(0, min(DAYS - 1, day))
    ts = rand_ts(day)
    u = random.choice(compromised_users) if category not in ("benign",) and random.random() < 0.5 else random.choice(users_df.user_id.tolist())
    host = random.choice(compromised_hosts) if category not in ("benign",) and random.random() < 0.5 else random.choice(hosts_df.host_id.tolist())
    proc = random.choice(MALICIOUS_PROCS)
    ip = f"10.{random.randint(1,20)}.{random.randint(0,254)}.{random.randint(2,254)}"
    text = tmpl.format(u=u, host=host, proc=proc, ip=ip)
    rows.append({
        "text_id": f"T{i:04d}",
        "timestamp": ts.isoformat(),
        "source_type": src_type,
        "category_label": category,
        "related_user": u,
        "related_host": host,
        "text_content": text,
        "is_ransomware_relevant": int(category in
                                       ("malware_alert", "credential_compromise", "backup_tampering",
                                        "ransomware_precursor", "ioc_report", "phishing_body", "phishing_report")),
    })
text_df = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
text_df.to_csv(f"{OUT}/text_soc_threatintel.csv", index=False)

users_df.to_csv(f"{OUT}/users_reference.csv", index=False)
hosts_df.to_csv(f"{OUT}/hosts_reference.csv", index=False)

print("Generated datasets:")
for name, df in [("email_gateway_logs", email_df), ("endpoint_edr_logs", endpoint_df),
                  ("identity_network_backup_logs", identity_df), ("text_soc_threatintel", text_df)]:
    print(f"  {name}: {len(df)} rows, columns={list(df.columns)[:6]}...")
print("Campaign ground truth ->", f"{OUT}/campaign_ground_truth.json")
