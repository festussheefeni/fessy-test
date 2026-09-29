"""
Supervised security model: classify ransomware precursor indicators
(phishing emails + malicious endpoint events) using Logistic Regression
baseline and XGBoost.
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
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (confusion_matrix, classification_report, roc_auc_score,
                              precision_recall_fscore_support, RocCurveDisplay)
from xgboost import XGBClassifier

DATA = "/home/claude/ransomguard/data"
OUT = "/home/claude/ransomguard/outputs"
FIG = "/home/claude/ransomguard/figures"
SEED = 42


def run_task(name, df, feature_cols, cat_cols, target_col, id_leak_cols):
    """Train/evaluate LR baseline + XGBoost on one classification task."""
    df = df.copy()
    X = df[feature_cols + cat_cols].copy()
    X = pd.get_dummies(X, columns=cat_cols, drop_first=True)
    y = df[target_col].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=SEED, stratify=y)

    # Logistic Regression baseline (scaled)
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)
    lr = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=SEED)
    lr.fit(X_train_s, y_train)
    lr_pred = lr.predict(X_test_s)
    lr_proba = lr.predict_proba(X_test_s)[:, 1]

    # XGBoost
    xgb = XGBClassifier(
        n_estimators=250, max_depth=4, learning_rate=0.08,
        subsample=0.9, colsample_bytree=0.9, eval_metric="logloss",
        random_state=SEED, scale_pos_weight=(y_train == 0).sum() / max((y_train == 1).sum(), 1))
    xgb.fit(X_train, y_train)
    xgb_pred = xgb.predict(X_test)
    xgb_proba = xgb.predict_proba(X_test)[:, 1]

    results = {}
    for model_name, y_pred, y_proba in [("logistic_regression", lr_pred, lr_proba),
                                          ("xgboost", xgb_pred, xgb_proba)]:
        cm = confusion_matrix(y_test, y_pred).tolist()
        p, r, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary", zero_division=0)
        acc = (np.array(y_pred) == y_test.values).mean()
        auc = roc_auc_score(y_test, y_proba)
        results[model_name] = {
            "confusion_matrix": cm, "confusion_matrix_labels": ["actual_0", "actual_1"],
            "accuracy": round(float(acc), 4), "precision": round(float(p), 4),
            "recall": round(float(r), 4), "f1_score": round(float(f1), 4),
            "roc_auc": round(float(auc), 4),
        }

    # Feature importance (XGBoost)
    importances = sorted(zip(X.columns, xgb.feature_importances_), key=lambda t: -t[1])[:12]
    results["xgboost"]["top_features"] = [{"feature": f, "importance": round(float(i), 4)} for f, i in importances]

    # Plots
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))
    for ax, (mname, y_pred) in zip(axes, [("Logistic Regression", lr_pred), ("XGBoost", xgb_pred)]):
        cm = confusion_matrix(y_test, y_pred)
        im = ax.imshow(cm, cmap="Blues")
        for (i, j), v in np.ndenumerate(cm):
            ax.text(j, i, str(v), ha="center", va="center",
                    color="white" if v > cm.max() / 2 else "black")
        ax.set_xticks([0, 1]); ax.set_xticklabels(["pred 0", "pred 1"])
        ax.set_yticks([0, 1]); ax.set_yticklabels(["actual 0", "actual 1"])
        ax.set_title(f"{mname} — {name}")
    plt.tight_layout()
    plt.savefig(f"{FIG}/{name}_confusion_matrices.png", dpi=130)
    plt.close()

    fig, ax = plt.subplots(figsize=(5.5, 4.5))
    RocCurveDisplay.from_predictions(y_test, lr_proba, name="Logistic Regression", ax=ax)
    RocCurveDisplay.from_predictions(y_test, xgb_proba, name="XGBoost", ax=ax)
    ax.set_title(f"ROC curve — {name}")
    plt.tight_layout()
    plt.savefig(f"{FIG}/{name}_roc_curve.png", dpi=130)
    plt.close()

    fig, ax = plt.subplots(figsize=(6, 4.5))
    feats, imps = zip(*importances)
    ax.barh(feats[::-1], imps[::-1], color="#1f77b4")
    ax.set_title(f"XGBoost feature importance — {name}")
    plt.tight_layout()
    plt.savefig(f"{FIG}/{name}_feature_importance.png", dpi=130)
    plt.close()

    return results


# ---------------------------------------------------------------------------
# Task 1: phishing email classification
# ---------------------------------------------------------------------------
email = read_csv_ts(f"{DATA}/email_gateway_logs.csv")
email_features = ["subject_length", "subject_has_urgency_kw", "embedded_url_count",
                   "attachment_count", "sender_is_external"]
email_cat = ["spf_result", "dkim_result", "dmarc_result"]
email_results = run_task("phishing_classification", email, email_features, email_cat, "label_phishing",
                          id_leak_cols=["email_id", "sender_hash", "recipient_hash", "recipient_user_id"])

# ---------------------------------------------------------------------------
# Task 2: malicious endpoint-event classification
# ---------------------------------------------------------------------------
endpoint = read_csv_ts(f"{DATA}/endpoint_edr_logs.csv")
endpoint_features = ["registry_change", "file_create_mod_count", "file_encryption_indicator",
                      "shadow_copy_deletion", "bytes_written"]
endpoint_cat = ["parent_process", "process_name"]
endpoint_results = run_task("endpoint_malicious_classification", endpoint, endpoint_features, endpoint_cat,
                             "label_malicious", id_leak_cols=["event_id", "host_id", "process_hash"])

all_results = {"phishing_classification": email_results, "endpoint_malicious_classification": endpoint_results}
with open(f"{OUT}/supervised_model_results.json", "w") as f:
    json.dump(all_results, f, indent=2)

print(json.dumps(all_results, indent=2))
