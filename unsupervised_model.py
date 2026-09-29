"""
Unsupervised / user-and-entity-behaviour analytics (UBA).
Isolation Forest scores per-user identity behaviour; DBSCAN clusters
per-host endpoint behaviour to flag hosts that fall outside normal
density clusters. Ground-truth labels (from the campaign) are used only
for post-hoc validation of the unsupervised output, never for training.
"""
import json
import sys
sys.path.insert(0, "/home/claude/ransomguard/src")
from util import read_csv_ts

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score

DATA = "/home/claude/ransomguard/data"
OUT = "/home/claude/ransomguard/outputs"
FIG = "/home/claude/ransomguard/figures"
SEED = 42

identity = read_csv_ts(f"{DATA}/identity_network_backup_logs.csv")
endpoint = read_csv_ts(f"{DATA}/endpoint_edr_logs.csv")

# ---------------------------------------------------------------------------
# Per-user behavioural aggregation (identity/network/backup)
# ---------------------------------------------------------------------------
identity["auth_fail"] = (identity.authentication_result == "failure").astype(int)
identity["mfa_bypassed_or_unused"] = identity.mfa_status.isin(["bypassed", "not_used"]).astype(int)
identity["priv_admin"] = identity.privilege_level.isin(["admin", "domain_admin"]).astype(int)
identity["backup_tamper"] = identity.backup_job_status.isin(["deleted", "failed", "disabled"]).astype(int)

user_agg = identity.groupby("user_id").agg(
    n_events=("record_id", "count"),
    auth_fail_rate=("auth_fail", "mean"),
    off_hours_rate=("off_hours_logon", "mean"),
    mfa_bypass_rate=("mfa_bypassed_or_unused", "mean"),
    admin_priv_rate=("priv_admin", "mean"),
    backup_tamper_rate=("backup_tamper", "mean"),
    mean_traffic=("traffic_volume_bytes", "mean"),
    distinct_hosts=("destination_host", "nunique"),
    any_suspicious_label=("label_suspicious", "max"),   # kept out-of-band for validation only
).reset_index()

feat_cols = ["auth_fail_rate", "off_hours_rate", "mfa_bypass_rate", "admin_priv_rate",
             "backup_tamper_rate", "mean_traffic", "distinct_hosts"]
X = StandardScaler().fit_transform(user_agg[feat_cols])

iso = IsolationForest(n_estimators=300, contamination=0.12, random_state=SEED)
iso.fit(X)
user_agg["anomaly_score"] = -iso.score_samples(X)          # higher = more anomalous
user_agg["anomaly_flag"] = (iso.predict(X) == -1).astype(int)

# Validate against ground truth (post-hoc only)
p, r, f1, _ = precision_recall_fscore_support(
    user_agg.any_suspicious_label, user_agg.anomaly_flag, average="binary", zero_division=0)
auc = roc_auc_score(user_agg.any_suspicious_label, user_agg.anomaly_score)
user_validation = {"precision": round(float(p), 4), "recall": round(float(r), 4),
                    "f1_score": round(float(f1), 4), "roc_auc": round(float(auc), 4),
                    "n_users": int(len(user_agg)), "n_flagged": int(user_agg.anomaly_flag.sum()),
                    "n_ground_truth_suspicious": int(user_agg.any_suspicious_label.sum())}

top_users = user_agg.sort_values("anomaly_score", ascending=False).head(15)
top_users.to_csv(f"{OUT}/top_anomalous_users.csv", index=False)

# ---------------------------------------------------------------------------
# Per-host behavioural clustering (endpoint) with DBSCAN
# ---------------------------------------------------------------------------
host_agg = endpoint.groupby("host_id").agg(
    n_events=("event_id", "count"),
    registry_change_rate=("registry_change", "mean"),
    mean_file_mod=("file_create_mod_count", "mean"),
    enc_indicator_rate=("file_encryption_indicator", "mean"),
    shadow_del_rate=("shadow_copy_deletion", "mean"),
    mean_bytes_written=("bytes_written", "mean"),
    any_malicious_label=("label_malicious", "max"),
).reset_index()

hfeat_cols = ["registry_change_rate", "mean_file_mod", "enc_indicator_rate",
              "shadow_del_rate", "mean_bytes_written"]
Xh = StandardScaler().fit_transform(host_agg[hfeat_cols])

db = DBSCAN(eps=1.4, min_samples=4)
host_agg["cluster"] = db.fit_predict(Xh)
host_agg["is_outlier"] = (host_agg.cluster == -1).astype(int)

p2, r2, f12, _ = precision_recall_fscore_support(
    host_agg.any_malicious_label, host_agg.is_outlier, average="binary", zero_division=0)
host_validation = {"precision": round(float(p2), 4), "recall": round(float(r2), 4),
                    "f1_score": round(float(f12), 4),
                    "n_hosts": int(len(host_agg)), "n_outlier_hosts": int(host_agg.is_outlier.sum()),
                    "n_clusters_found": int(host_agg.cluster.nunique() - (1 if -1 in host_agg.cluster.values else 0)),
                    "n_ground_truth_malicious_hosts": int(host_agg.any_malicious_label.sum())}

host_agg.sort_values("is_outlier", ascending=False).to_csv(f"{OUT}/host_cluster_results.csv", index=False)

validation = {"user_isolation_forest": user_validation, "host_dbscan": host_validation}
with open(f"{OUT}/unsupervised_model_results.json", "w") as f:
    json.dump(validation, f, indent=2)

# ---------------------------------------------------------------------------
# Plots
# ---------------------------------------------------------------------------
pca = PCA(n_components=2, random_state=SEED)
Xp = pca.fit_transform(X)
fig, ax = plt.subplots(figsize=(6.5, 5))
sc = ax.scatter(Xp[:, 0], Xp[:, 1], c=user_agg.anomaly_score, cmap="Reds", s=45, edgecolor="k", linewidth=0.3)
plt.colorbar(sc, label="Isolation Forest anomaly score")
ax.set_title("User behavioural anomaly score (PCA projection)")
ax.set_xlabel("PC1"); ax.set_ylabel("PC2")
plt.tight_layout()
plt.savefig(f"{FIG}/05_user_anomaly_pca.png", dpi=130)
plt.close()

Xph = PCA(n_components=2, random_state=SEED).fit_transform(Xh)
fig, ax = plt.subplots(figsize=(6.5, 5))
sc = ax.scatter(Xph[:, 0], Xph[:, 1], c=host_agg.cluster, cmap="tab10", s=60, edgecolor="k", linewidth=0.3)
ax.set_title("Host behavioural clusters (DBSCAN, PCA projection)")
ax.set_xlabel("PC1"); ax.set_ylabel("PC2")
plt.tight_layout()
plt.savefig(f"{FIG}/06_host_dbscan_clusters.png", dpi=130)
plt.close()

print(json.dumps(validation, indent=2))
print("\nTop anomalous users:\n", top_users[["user_id", "anomaly_score", "any_suspicious_label"]].to_string(index=False))
