"""Baseline / exploratory data analysis for RansomGuard datasets."""
import json
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

DATA = "/home/claude/ransomguard/data"
FIG = "/home/claude/ransomguard/figures"
OUT = "/home/claude/ransomguard/outputs"

def _read(path):
    df = pd.read_csv(path)
    df["timestamp"] = pd.to_datetime(df["timestamp"], format="ISO8601")
    return df

email = _read(f"{DATA}/email_gateway_logs.csv")
endpoint = _read(f"{DATA}/endpoint_edr_logs.csv")
identity = _read(f"{DATA}/identity_network_backup_logs.csv")
text = _read(f"{DATA}/text_soc_threatintel.csv")

quality = {}
for name, df in [("email_gateway_logs", email), ("endpoint_edr_logs", endpoint),
                  ("identity_network_backup_logs", identity), ("text_soc_threatintel", text)]:
    quality[name] = {
        "rows": int(len(df)),
        "date_range": [str(df.timestamp.min()), str(df.timestamp.max())],
        "null_counts": {k: int(v) for k, v in df.isna().sum().to_dict().items() if v > 0},
        "duplicate_rows": int(df.duplicated().sum()),
    }
with open(f"{OUT}/data_quality_report.json", "w") as f:
    json.dump(quality, f, indent=2)

# Daily event-volume baseline (all sources)
fig, axes = plt.subplots(3, 1, figsize=(9, 9), sharex=True)
email.set_index("timestamp").resample("D").size().plot(ax=axes[0], color="#1f77b4")
axes[0].set_title("Daily email volume (gateway logs)")
endpoint.set_index("timestamp").resample("D").size().plot(ax=axes[1], color="#d62728")
axes[1].set_title("Daily endpoint/EDR event volume")
identity.set_index("timestamp").resample("D").size().plot(ax=axes[2], color="#2ca02c")
axes[2].set_title("Daily identity/network/backup record volume")
axes[2].set_xlabel("Date")
for ax in axes:
    ax.axvspan(pd.Timestamp("2026-08-31"), pd.Timestamp("2026-09-08"),
                color="orange", alpha=0.15, label="campaign window (20-28 elapsed days)")
plt.tight_layout()
plt.savefig(f"{FIG}/01_daily_volume_baseline.png", dpi=130)
plt.close()

# Phishing indicator distribution
fig, ax = plt.subplots(1, 2, figsize=(10, 4))
email.groupby("label_phishing").embedded_url_count.mean().plot(kind="bar", ax=ax[0], color=["#2ca02c", "#d62728"])
ax[0].set_xticklabels(["benign", "phishing"], rotation=0)
ax[0].set_title("Mean embedded URL count")
pd.crosstab(email.label_phishing, email.spf_result).plot(kind="bar", stacked=True, ax=ax[1])
ax[1].set_xticklabels(["benign", "phishing"], rotation=0)
ax[1].set_title("SPF result by class")
plt.tight_layout()
plt.savefig(f"{FIG}/02_email_indicator_distributions.png", dpi=130)
plt.close()

# Off-hours logons over time (identity)
fig, ax = plt.subplots(figsize=(9, 4))
identity.set_index("timestamp").resample("D").off_hours_logon.sum().plot(ax=ax, color="#9467bd")
ax.set_title("Off-hours logon count per day")
ax.set_ylabel("count")
plt.tight_layout()
plt.savefig(f"{FIG}/03_offhours_logons_timeseries.png", dpi=130)
plt.close()

# Endpoint malicious-process indicator correlation heatmap-ish (simple corr matrix)
num_cols = ["registry_change", "file_create_mod_count", "file_encryption_indicator",
            "shadow_copy_deletion", "bytes_written", "label_malicious"]
corr = endpoint[num_cols].corr()
fig, ax = plt.subplots(figsize=(6, 5))
im = ax.imshow(corr, cmap="RdBu_r", vmin=-1, vmax=1)
ax.set_xticks(range(len(num_cols))); ax.set_xticklabels(num_cols, rotation=45, ha="right")
ax.set_yticks(range(len(num_cols))); ax.set_yticklabels(num_cols)
plt.colorbar(im)
ax.set_title("Endpoint feature correlation with malicious label")
plt.tight_layout()
plt.savefig(f"{FIG}/04_endpoint_feature_correlation.png", dpi=130)
plt.close()

print("EDA complete.")
print(json.dumps(quality, indent=2))
