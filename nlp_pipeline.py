"""
Text mining / NLP: classify SOC tickets, phishing-email bodies and threat-intel
narratives as ransomware-relevant vs not, extract simple named indicators
(hosts, users, process names) and run topic modelling (NMF) over the corpus.
"""
import json
import re
import sys
sys.path.insert(0, "/home/claude/ransomguard/src")
from util import read_csv_ts

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_recall_fscore_support, accuracy_score
from sklearn.decomposition import NMF

DATA = "/home/claude/ransomguard/data"
OUT = "/home/claude/ransomguard/outputs"
FIG = "/home/claude/ransomguard/figures"
SEED = 42

text = read_csv_ts(f"{DATA}/text_soc_threatintel.csv")

# ---------------------------------------------------------------------------
# Entity/indicator extraction (regex-based, lightweight NER substitute)
# ---------------------------------------------------------------------------
HOST_RE = re.compile(r"HOST-\d{4}")
USER_RE = re.compile(r"U\d{4}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PROC_RE = re.compile(r"\b[\w]+\.exe\b", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b[\w-]+\.(?:com|net|biz|info|co\.za)\b", re.IGNORECASE)

def extract(t):
    return {
        "hosts": sorted(set(HOST_RE.findall(t))),
        "users": sorted(set(USER_RE.findall(t))),
        "ips": sorted(set(IP_RE.findall(t))),
        "processes": sorted(set(p.lower() for p in PROC_RE.findall(t))),
        "domains": sorted(set(d.lower() for d in DOMAIN_RE.findall(t))),
    }

text["extracted_indicators"] = text.text_content.apply(lambda t: extract(t))
n_with_indicators = int((text.extracted_indicators.apply(lambda d: any(len(v) for v in d.values()))).sum())

# ---------------------------------------------------------------------------
# TF-IDF + Logistic Regression classification: ransomware-relevant vs not
# ---------------------------------------------------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    text.text_content, text.is_ransomware_relevant, test_size=0.25,
    random_state=SEED, stratify=text.is_ransomware_relevant)

vec = TfidfVectorizer(max_features=400, stop_words="english", ngram_range=(1, 2), min_df=2)
Xtr = vec.fit_transform(X_train)
Xte = vec.transform(X_test)

clf = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=SEED)
clf.fit(Xtr, y_train)
y_pred = clf.predict(Xte)

p, r, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary", zero_division=0)
acc = accuracy_score(y_test, y_pred)

# top predictive terms
coefs = clf.coef_[0]
terms = np.array(vec.get_feature_names_out())
top_pos = terms[np.argsort(coefs)[-12:]][::-1]
top_neg = terms[np.argsort(coefs)[:12]]

classification_results = {
    "accuracy": round(float(acc), 4), "precision": round(float(p), 4),
    "recall": round(float(r), 4), "f1_score": round(float(f1), 4),
    "n_train": int(len(X_train)), "n_test": int(len(X_test)),
    "top_ransomware_relevant_terms": top_pos.tolist(),
    "top_benign_terms": top_neg.tolist(),
}

# ---------------------------------------------------------------------------
# Topic modelling (NMF) over the full corpus
# ---------------------------------------------------------------------------
vec_full = TfidfVectorizer(max_features=300, stop_words="english", ngram_range=(1, 2), min_df=2)
X_full = vec_full.fit_transform(text.text_content)
n_topics = 5
nmf = NMF(n_components=n_topics, random_state=SEED, init="nndsvda", max_iter=500)
W = nmf.fit_transform(X_full)
H = nmf.components_
terms_full = np.array(vec_full.get_feature_names_out())

topics = []
for k in range(n_topics):
    top_terms = terms_full[np.argsort(H[k])[-8:]][::-1].tolist()
    topics.append({"topic_id": k, "top_terms": top_terms})
text["dominant_topic"] = W.argmax(axis=1)

topic_by_category = pd.crosstab(text.dominant_topic, text.category_label)
topic_by_category.to_csv(f"{OUT}/nlp_topic_by_category.csv")

nlp_results = {"classification": classification_results,
               "topics": topics,
               "n_records": int(len(text)),
               "n_records_with_extracted_indicators": n_with_indicators}
with open(f"{OUT}/nlp_results.json", "w") as f:
    json.dump(nlp_results, f, indent=2)

# sample of extracted indicators for the report
text[["text_id", "source_type", "category_label", "extracted_indicators"]].head(15).to_json(
    f"{OUT}/nlp_sample_extractions.json", orient="records", indent=2)

# ---------------------------------------------------------------------------
# Plot: topic distribution by category
# ---------------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(8, 5))
topic_by_category.plot(kind="bar", stacked=True, ax=ax, colormap="tab20")
ax.set_title("NMF topic distribution by SOC/threat-intel category")
ax.set_xlabel("Dominant topic"); ax.set_ylabel("Record count")
ax.legend(bbox_to_anchor=(1.02, 1), loc="upper left", fontsize=7)
plt.tight_layout()
plt.savefig(f"{FIG}/07_nlp_topic_distribution.png", dpi=130)
plt.close()

print(json.dumps(nlp_results, indent=2))
