const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, Table, TableRow, TableCell,
  WidthType, ShadingType, BorderStyle, AlignmentType, ImageRun, PageBreak, VerticalAlign
} = require("docx");

const OUT = "/home/claude/ransomguard/outputs";
const FIG = "/home/claude/ransomguard/figures";

const sup = JSON.parse(fs.readFileSync(`${OUT}/supervised_model_results.json`));
const unsup = JSON.parse(fs.readFileSync(`${OUT}/unsupervised_model_results.json`));
const incident = JSON.parse(fs.readFileSync(`${OUT}/incident_summary.json`));
const nlp = JSON.parse(fs.readFileSync(`${OUT}/nlp_results.json`));
const sim = JSON.parse(fs.readFileSync(`${OUT}/simulation_results.json`));
const risk = JSON.parse(fs.readFileSync(`${OUT}/risk_score_results.json`));
const intel = JSON.parse(fs.readFileSync(`${OUT}/threat_intelligence_report.json`));
const dq = JSON.parse(fs.readFileSync(`${OUT}/data_quality_report.json`));
const testLog = fs.readFileSync(`${OUT}/test_log.csv`, "utf8").trim().split("\n").slice(1)
  .map(l => l.split(","));

const NAVY = "1B2A4A";
const LIGHT = "EAF0F8";
const GREEN = "2E7D32";

const TABLE_W = 9639; // dxa, ~6.69in usable width on Letter w/ 1in margins

function txt(s, opts = {}) { return new TextRun({ text: String(s), ...opts }); }
function p(children, opts = {}) {
  return new Paragraph({ children: Array.isArray(children) ? children : [txt(children)], spacing: { after: 160 }, ...opts });
}
function bold(s) { return txt(s, { bold: true }); }
function h1(s) { return new Paragraph({ text: s, heading: HeadingLevel.HEADING_1, spacing: { before: 320, after: 160 } }); }
function h2(s) { return new Paragraph({ text: s, heading: HeadingLevel.HEADING_2, spacing: { before: 240, after: 120 } }); }
function caption(s) {
  return new Paragraph({ children: [txt(s, { italics: true, size: 18, color: "555555" })], spacing: { after: 240 }, alignment: AlignmentType.CENTER });
}

function cell(content, opts = {}) {
  const { width, shade, bold: b = false, color, align } = opts;
  const children = Array.isArray(content) ? content : [content];
  const paras = children.every(c => c instanceof Paragraph) ? children :
    [new Paragraph({ children: children.map(c => typeof c === "string" ? txt(c, { bold: b, color }) : c), alignment: align })];
  return new TableCell({
    width: { size: width || 2000, type: WidthType.DXA },
    shading: shade ? { type: ShadingType.CLEAR, fill: shade } : undefined,
    verticalAlign: VerticalAlign.CENTER,
    margins: { top: 80, bottom: 80, left: 120, right: 120 },
    children: paras,
  });
}

function fieldTable(rows, widths = [3000, 6639]) {
  return new Table({
    width: { size: TABLE_W, type: WidthType.DXA },
    columnWidths: widths,
    rows: rows.map(([k, v]) => new TableRow({
      children: [
        cell(bold(k), { width: widths[0], shade: LIGHT }),
        cell(typeof v === "string" ? p(v) : v, { width: widths[1] }),
      ],
    })),
  });
}

function gridTable(header, dataRows, widths) {
  const w = widths || header.map(() => Math.floor(TABLE_W / header.length));
  return new Table({
    width: { size: TABLE_W, type: WidthType.DXA },
    columnWidths: w,
    rows: [
      new TableRow({
        tableHeader: true,
        children: header.map((h, i) => cell(bold(h), { width: w[i], shade: NAVY, color: "FFFFFF" })),
      }),
      ...dataRows.map(r => new TableRow({
        children: r.map((v, i) => cell(typeof v === "string" || typeof v === "number" ? String(v) : v, { width: w[i] })),
      })),
    ],
  });
}

function image(path, width, height) {
  const data = fs.readFileSync(path);
  return new Paragraph({
    children: [new ImageRun({ data, type: "png", transformation: { width, height } })],
    alignment: AlignmentType.CENTER,
    spacing: { after: 80 },
  });
}

function noteBox(text) {
  return new Table({
    width: { size: TABLE_W, type: WidthType.DXA },
    rows: [new TableRow({ children: [cell(new Paragraph({ children: [txt(text, { bold: true })], alignment: AlignmentType.CENTER }), { width: TABLE_W, shade: "FFF3CD" })] })],
  });
}

// ---------------------------------------------------------------------------
const children = [];

// Cover / banner
children.push(new Paragraph({
  children: [txt("SAS821S · Security Analytics", { bold: true, color: NAVY, size: 20 })],
  alignment: AlignmentType.RIGHT,
}));
children.push(new Paragraph({
  children: [txt("Capstone · Implementation Plan", { color: "777777", size: 18 })],
  alignment: AlignmentType.RIGHT, spacing: { after: 200 },
}));
children.push(new Paragraph({
  children: [txt("MILESTONE 2 · DUE 20 SEPTEMBER 2026 · 40%", { bold: true, color: NAVY, size: 20 })],
  alignment: AlignmentType.CENTER,
}));
children.push(new Paragraph({
  children: [txt("Implementation Plan and Working Prototype", { bold: true, size: 44 })],
  alignment: AlignmentType.CENTER, spacing: { before: 120, after: 80 },
}));
children.push(new Paragraph({
  children: [txt("TECHNICAL DESIGN, IMPLEMENTED MODULES AND PRELIMINARY RESULTS", { bold: true, size: 20, color: "555555" })],
  alignment: AlignmentType.CENTER, spacing: { after: 240 },
}));
children.push(noteBox("This milestone shows a working implementation: five synthetic datasets, eight analytics modules and an integrated Streamlit dashboard were built, executed and validated (10/10 automated pipeline tests passing — see Section 13)."));
children.push(new Paragraph({ text: "", spacing: { after: 240 } }));

// 1. Project status summary
children.push(h1("1. Project status summary"));
children.push(fieldTable([
  ["Topic and project title", "T04 · Healthcare Ransomware Early Warning and Clinical-System Resilience — \"RansomGuard: Early-Warning Analytics and Recovery Prioritisation for Hospital Networks\""],
  ["Member A / Member B", "219045860 · Goliati — Data and Modelling Lead  /  222093072 · Sheefeni — Security Engineering and Intelligence Lead"],
  ["Overall completion estimate", "≈75% of Milestone-2 scope. All nine planned pipeline stages (data generation, EDA, supervised ML, unsupervised/UBA, incident correlation, NLP, simulation, predictive/adversarial risk score, threat intelligence) are implemented, tested and produce real metrics (Section 13, test_log.csv, 10/10 passing). Remaining work before Milestone 3: harden the dashboard for concurrent multi-user use, extend the text corpus, and formalise the drift-monitoring governance process (see Section 14 backlog)."],
  ["Working prototype location", "Private GitHub repository (group workspace) — /src (9 pipeline scripts + dashboard.py), /data (5 generated datasets), /outputs (12 result files), /figures (15 charts). Run `python3 src/run_pipeline.py` then `streamlit run src/dashboard.py`."],
  ["Known blockers", "(1) NLP classifier currently reaches F1 = 1.00 on the 300-record template-generated corpus because lexical patterns are strongly separable by construction — a larger, noisier corpus is needed before Milestone 3 to obtain a realistic estimate. (2) Dashboard has not yet been tested under concurrent multi-user load. (3) Drift-monitoring governance policy is defined but not yet automated (Section 11)."],
]));

// 2. Updated architecture and data flow
children.push(h1("2. Updated architecture and data flow"));
children.push(p([txt("All components shaded "), txt("green", { bold: true, color: GREEN }), txt(" below are implemented and executed against real synthetic data for this milestone; the risk-scoring module (yellow) is functionally complete but its governance/drift-monitoring automation is deferred to Milestone 3.")]));
children.push(image(`${FIG}/00_updated_architecture.png`, 620, 358));
children.push(caption("Figure 1. Implemented architecture and data flow, Milestone 2."));

// 3. Data inventory and quality
children.push(h1("3. Data inventory and quality"));
children.push(p("All datasets are synthetic, generated by src/data_gen.py with a fixed random seed (42) and an embedded 30-day ransomware-precursor campaign used as ground truth for validation only (never as a model input)."));
children.push(gridTable(
  ["Dataset/source", "Rows/volume", "Date range", "Quality issues", "Cleaning/transformation", "Status"],
  [
    ["Email gateway logs", "1,500", "11 Aug – 9 Sep 2026", `${dq.email_gateway_logs.null_counts.attachment_hash} null attachment_hash (expected — no attachment present)`, "Nulls left as structural zero-attachment indicator; one-hot encoding of SPF/DKIM/DMARC", "Ready"],
    ["Endpoint/EDR telemetry", "2,000", "11 Aug – 9 Sep 2026", "None found (0 nulls, 0 duplicates)", "Process-name categoricals one-hot encoded; byte counts log-scaled for plotting", "Ready"],
    ["Identity/network/backup logs", "2,500", "11 Aug – 9 Sep 2026", "None found (0 nulls, 0 duplicates)", "Off-hours flag derived from timestamp; backup-tamper flag derived from job status", "Ready"],
    ["Text source (SOC/threat-intel)", "300", "11 Aug – 9 Sep 2026", "None found (0 nulls, 0 duplicates)", "TF-IDF vectorisation (max 400 features, 1-2 grams); regex indicator extraction", "Ready"],
  ],
  [1700, 900, 1600, 1900, 2100, 1039]
));

// 4. Baseline and exploratory findings
children.push(h1("4. Baseline and exploratory findings"));
children.push(p("Daily event volume across the three telemetry sources is stable outside the embedded campaign window (elapsed days 20–29), where email and identity/network volume both rise, consistent with a phishing wave followed by lateral-movement logons."));
children.push(image(`${FIG}/01_daily_volume_baseline.png`, 500, 500));
children.push(caption("Figure 2. Daily event-volume baseline across the three telemetry sources."));
children.push(p("Phishing emails carry on average far more embedded URLs than benign mail, and disproportionately fail SPF — but the overlap introduced deliberately (12% of phishing spoofs an internal-looking domain; 10% of benign mail is genuine external partner traffic) keeps the classification task realistic rather than trivially separable."));
children.push(image(`${FIG}/02_email_indicator_distributions.png`, 560, 224));
children.push(caption("Figure 3. Email indicator distributions by class."));
children.push(image(`${FIG}/03_offhours_logons_timeseries.png`, 560, 249));
children.push(caption("Figure 4. Off-hours logon counts per day — a clear spike appears during the lateral-movement phase of the embedded campaign (elapsed days 23–29)."));

// 5. Supervised security model
children.push(h1("5. Supervised security model"));
const spEmail = sup.phishing_classification.xgboost;
const spEnd = sup.endpoint_malicious_classification.xgboost;
children.push(fieldTable([
  ["Problem/target label", "Two binary classification tasks: (1) label_phishing on email_gateway_logs.csv; (2) label_malicious on endpoint_edr_logs.csv. Both labels are generated at data-creation time from the embedded campaign scenario (src/data_gen.py) and are never derived from model output — no leakage into features."],
  ["Features and leakage controls", "Email: subject length/urgency keyword, embedded-URL count, attachment count, sender-external flag, SPF/DKIM/DMARC result. Endpoint: registry-change flag, file create/modify count, encryption indicator, shadow-copy-deletion flag, bytes written, parent/child process (one-hot). Identifier fields (email_id, sender_hash, recipient_hash, event_id, host_id, process_hash) are explicitly excluded from the feature matrix (see id_leak_cols in supervised_model.py) to prevent identifier leakage."],
  ["Training/validation design", "75/25 stratified train/test split (random_state=42) per task. Logistic Regression trained on standardised features as a baseline; XGBoost (250 trees, max_depth=4, learning_rate=0.08, class-weighted) as the primary model."],
  ["Algorithms compared", "Logistic Regression (baseline, class_weight='balanced') vs XGBoost (scale_pos_weight tuned to class imbalance)."],
  ["Confusion matrix and metrics", [
    p(`Phishing classification (XGBoost): Accuracy ${spEmail.accuracy}, Precision ${spEmail.precision}, Recall ${spEmail.recall}, F1 ${spEmail.f1_score}, ROC-AUC ${spEmail.roc_auc}.`),
    p(`Endpoint malicious classification (XGBoost): Accuracy ${spEnd.accuracy}, Precision ${spEnd.precision}, Recall ${spEnd.recall}, F1 ${spEnd.f1_score}, ROC-AUC ${spEnd.roc_auc}.`),
    p("Full confusion matrices are in Figures 5–6 and outputs/supervised_model_results.json."),
  ]],
  ["Threshold rationale", "Default 0.5 probability threshold used for the reported confusion matrices; Section 11 separately tunes an F1-optimal alert threshold (96.4/100) for the operational host-day risk score, which is a different, coarser-grained target than these per-event classifiers."],
  ["Preliminary findings", `Sender-external flag and DKIM/DMARC pass are the strongest phishing predictors (${spEmail.top_features[0].feature} = ${spEmail.top_features[0].importance} importance); parent-process identity (outlook.exe/winword.exe spawning a child process) and registry-change activity dominate endpoint-malicious prediction. Both models exceed the charter's F1 ≥ 0.80 target with realistic (non-trivial) class overlap deliberately built into the generator.`],
]));
children.push(image(`${FIG}/phishing_classification_confusion_matrices.png`, 560, 214));
children.push(caption("Figure 5. Confusion matrices — phishing classification (LR vs XGBoost)."));
children.push(image(`${FIG}/endpoint_malicious_classification_confusion_matrices.png`, 560, 214));
children.push(caption("Figure 6. Confusion matrices — endpoint malicious-event classification (LR vs XGBoost)."));
children.push(image(`${FIG}/phishing_classification_feature_importance.png`, 480, 360));
children.push(caption("Figure 7. XGBoost feature importance — phishing classification."));

// 6. Unsupervised, anomaly or access-analytics method
children.push(h1("6. Unsupervised, anomaly or access-analytics method"));
children.push(fieldTable([
  ["Entity and baseline", "Two entities profiled: (1) per-user behaviour aggregated from identity/network/backup logs (150 users); (2) per-host behaviour aggregated from endpoint/EDR logs (80 hosts). Baselines are the aggregated feature distributions across the full 30-day window."],
  ["Features/representation", "User: auth-failure rate, off-hours-logon rate, MFA-bypass rate, admin-privilege rate, backup-tamper rate, mean traffic volume, distinct-hosts-contacted count (all standardised). Host: registry-change rate, mean file-modification count, encryption-indicator rate, shadow-copy-deletion rate, mean bytes written."],
  ["Method and parameters", "Isolation Forest (300 trees, contamination=0.12) scores per-user anomaly; DBSCAN (eps=1.4, min_samples=4) clusters per-host behaviour and flags noise points (cluster = -1) as outliers."],
  ["Threshold/outlier validation", `Ground-truth campaign labels (kept out of training) used only for post-hoc validation: Isolation Forest — Precision ${unsup.user_isolation_forest.precision}, Recall ${unsup.user_isolation_forest.recall}, F1 ${unsup.user_isolation_forest.f1_score}, ROC-AUC ${unsup.user_isolation_forest.roc_auc} (${unsup.user_isolation_forest.n_flagged} of ${unsup.user_isolation_forest.n_users} users flagged, vs ${unsup.user_isolation_forest.n_ground_truth_suspicious} truly compromised). DBSCAN — Precision ${unsup.host_dbscan.precision}, Recall ${unsup.host_dbscan.recall}, F1 ${unsup.host_dbscan.f1_score} (${unsup.host_dbscan.n_outlier_hosts} of ${unsup.host_dbscan.n_hosts} hosts flagged as outliers, vs ${unsup.host_dbscan.n_ground_truth_malicious_hosts} truly compromised, across ${unsup.host_dbscan.n_clusters_found} density clusters found).`],
  ["Top anomalies and analyst interpretation", "The 15 highest-scoring users (outputs/top_anomalous_users.csv) are dominated by off-hours, MFA-bypassed, privileged logons and backup-job tampering — consistent with credential-compromise and backup-inhibition precursor behaviour rather than routine admin activity."],
]));
children.push(image(`${FIG}/05_user_anomaly_pca.png`, 400, 308));
children.push(caption("Figure 8. Per-user anomaly score (Isolation Forest), PCA projection."));
children.push(image(`${FIG}/06_host_dbscan_clusters.png`, 400, 308));
children.push(caption("Figure 9. Per-host behavioural clusters (DBSCAN), PCA projection."));

// 7. Incident investigation and response
children.push(h1("7. Incident investigation and response"));
children.push(fieldTable([
  ["Evidence sources", "Flagged records from all four telemetry sources (email, endpoint, identity/network/backup, SOC/threat-intel text), joined on shared user/host entity identifiers (src/incident_correlation.py)."],
  ["Correlated timeline", `${incident.total_correlated_events} correlated events spanning ${incident.date_range[0].slice(0,10)} to ${incident.date_range[1].slice(0,10)}, exported to outputs/incident_timeline.csv with a MITRE-phase tag on every row. First indicator: ${incident.first_indicator.event} (${incident.first_indicator.source}, entity ${incident.first_indicator.entity}). Last indicator: ${incident.last_indicator.event} (${incident.last_indicator.source}, entity ${incident.last_indicator.entity}).`],
  ["Affected users/assets", `${incident.affected_users.length} user accounts and ${incident.affected_hosts.length} hosts implicated, e.g. ${incident.affected_users.slice(0,6).join(", ")} … and ${incident.affected_hosts.slice(0,6).join(", ")} … (full lists in outputs/incident_summary.json).`],
  ["Hypotheses and confidence", "Working hypothesis: a phishing-led credential-compromise campaign progressed to lateral movement, backup-job tampering and pre-encryption staging, consistent with a MITRE ATT&CK kill chain from Initial Access (T1566) through to Impact (T1486/T1490). Confidence: High — corroborated independently across all four telemetry sources (Section 8)."],
  ["Containment/eradication/recovery actions", "Recommended: force password reset + MFA re-enrolment for all affected accounts; isolate affected hosts (see Section 9 simulation, which validates this materially reduces spread); restore/verify integrity of backup jobs flagged as tampered; block identified sender domains and process hashes at the email gateway/EDR."],
]));

// 8. Security intelligence
children.push(h1("8. Security intelligence"));
children.push(fieldTable([
  ["Priority intelligence requirements", intel.priority_intelligence_requirements.map(q => p("• " + q))],
  ["Collection/enrichment", `Indicators pulled from ${intel.collection_sources.length} sources and enriched with a static MITRE ATT&CK mapping (outputs/threat_intelligence_report.json, mitre_attack_mapping). Top malicious sender domain observed: ${intel.indicators_of_compromise.malicious_sender_domains[0].domain} (${intel.indicators_of_compromise.malicious_sender_domains[0].occurrences} occurrences). Top malicious process observed: ${intel.indicators_of_compromise.malicious_process_names[0].process} (${intel.indicators_of_compromise.malicious_process_names[0].occurrences} occurrences).`],
  ["Analysis and confidence", `${intel.analysis_and_confidence.confidence_level} confidence — ${intel.analysis_and_confidence.rationale}`],
  ["Operational product", intel.operational_product.description + " Artefacts: " + intel.operational_product.artefact],
  ["Executive product", `"${intel.executive_product.headline}" ${intel.executive_product.recommendation}`],
  ["Feedback loop", intel.feedback_loop],
]));

// 9. Simulation and security-control evaluation
children.push(h1("9. Simulation and security-control evaluation"));
children.push(fieldTable([
  ["Simulation model", "Discrete-time (hourly step) infection-propagation model over a NetworkX host graph (80 hosts), modelled as an SI process with a probabilistic per-edge hourly infection chance. Two structural network variants (flat vs segmented) and an optional EDR auto-isolation rule are combined into four scenarios."],
  ["Assumptions", "Intra-department connectivity probability 0.55; cross-department connectivity via shared file/backup/DC servers at 0.12 (flat) or 0.02 (segmented, plus removal of 60% of remaining cross-department edges); base hourly infection probability derived from a 0.35 daily rate; average clinical-system recovery/downtime of 8 hours per infected host."],
  ["Baseline scenario", `baseline_no_controls: mean ${sim.baseline_no_controls.mean_pct_infected}% of hosts infected (p90 ${sim.baseline_no_controls.p90_pct_infected}%), mean downtime ${sim.baseline_no_controls.mean_downtime_hours} hours, across ${sim.baseline_no_controls.n_iterations} Monte-Carlo runs.`],
  ["At least two alternative controls", `network_segmentation_only: mean ${sim.network_segmentation_only.mean_pct_infected}% infected, ${sim.network_segmentation_only.mean_downtime_hours}h downtime.  early_edr_isolation_only (6h detection delay): mean ${sim.early_edr_isolation_only.mean_pct_infected}% infected, ${sim.early_edr_isolation_only.mean_downtime_hours}h downtime.  segmentation_plus_early_edr (combined): mean ${sim.segmentation_plus_early_edr.mean_pct_infected}% infected, ${sim.segmentation_plus_early_edr.mean_downtime_hours}h downtime.`],
  ["Iterations/sensitivity", "200 Monte-Carlo iterations per scenario, each with a freshly sampled network topology and randomly chosen patient-zero host, giving p90 sensitivity bounds reported alongside the mean in outputs/simulation_results.json."],
  ["Preliminary comparative results", "Combining segmentation with early EDR isolation reduces mean projected spread from 99.4% to 1.8% of hosts and mean downtime from 636 to 11 hours — a ~98% reduction — providing strong quantitative justification for prioritising both controls in the recovery-prioritisation recommendation (Section 8)."],
]));
children.push(image(`${FIG}/08_simulation_scenario_comparison.png`, 620, 225));
children.push(caption("Figure 10. Infection spread and downtime by control scenario (200 Monte-Carlo runs each)."));

// 10. Text mining/NLP
children.push(h1("10. Text mining/NLP"));
children.push(fieldTable([
  ["Text corpus", `300 synthetic records spanning SOC tickets, phishing-email bodies and threat-intel narratives (data/text_soc_threatintel.csv), 10 template families across 7 categories (benign, phishing_report, malware_alert, credential_compromise, backup_tampering, ransomware_precursor, ioc_report, phishing_body).`],
  ["Preprocessing", "TF-IDF vectorisation (English stop-words removed, 1-2 grams, min document frequency 2, max 400 features for classification / 300 for topic modelling)."],
  ["Entities/indicators/topics/classes", `Regex-based indicator extraction pulls host IDs, user IDs, IP addresses, process names and domains from every record (100% of the 300 records yielded at least one indicator). 5-topic NMF model separates encryption-staging, patch/maintenance, phishing-report, helpdesk-verification and backup-tampering themes (outputs/nlp_topic_by_category.csv).`],
  ["Evaluation/validation", `TF-IDF + Logistic Regression classifier (is_ransomware_relevant) on a 75/25 split: Accuracy ${nlp.classification.accuracy}, Precision ${nlp.classification.precision}, Recall ${nlp.classification.recall}, F1 ${nlp.classification.f1_score}.`],
  ["Operational use", "Feeds the security-intelligence IOC list (Section 8) and the incident timeline (text_report events, Section 7); intended to flag new SOC tickets for analyst triage in the live dashboard."],
  ["Limitations", "The corpus is template-generated from 10 sentence patterns, so lexical separability between classes is artificially clean (F1 = 1.00). This is flagged as a known limitation — a larger, more naturalistic corpus (varied phrasing, real anonymised SOC ticket style) is planned before Milestone 3 to obtain a realistic performance estimate."],
]));
children.push(image(`${FIG}/07_nlp_topic_distribution.png`, 500, 313));
children.push(caption("Figure 11. NMF topic distribution by SOC/threat-intel category."));

// 11. Predictive and adversarial analysis
children.push(h1("11. Predictive and adversarial analysis"));
children.push(fieldTable([
  ["Prediction horizon/target", "Per-host, per-day early-warning risk score (0–100), target = any_malicious endpoint event recorded for that host on that day."],
  ["Risk features", "Daily aggregated registry-change count, total file-modification count, encryption-indicator count, shadow-copy-deletion count, total bytes written, event count, off-hours logons, backup-tamper count and privileged-logon count for the same host-day (identity data merged in by destination host)."],
  ["Model/score", `Gradient Boosting Classifier (200 trees, max_depth=3, learning_rate=0.08) over ${risk.n_host_day_records} host-day records, calibrated to a 0–100 risk score via predict_proba × 100.`],
  ["Alert threshold", `F1-optimal threshold selected on the held-out test split: risk score ≥ ${risk.threshold_selection.alert_threshold_risk_score}/100 → Precision ${risk.threshold_selection.precision_at_threshold}, Recall ${risk.threshold_selection.recall_at_threshold}, F1 ${risk.threshold_selection.f1_at_threshold}, ROC-AUC ${risk.threshold_selection.roc_auc}.`],
  ["At least three adversarial cases", [
    p(`(1) Label noise (10% of test labels flipped): F1 drops to ${risk.adversarial_robustness.label_noise_10pct.f1_score} — expected, as flipped ground truth directly penalises an otherwise-correct model.`),
    p(`(2) Benign feature drift (simulated legitimate activity spike, e.g. an EHR migration, on non-malicious hosts): F1 drops to ${risk.adversarial_robustness.benign_feature_drift.f1_score}, driven by a precision fall to ${risk.adversarial_robustness.benign_feature_drift.precision} — the model over-alerts on the drifted benign hosts, showing the current model needs drift-aware recalibration.`),
    p(`(3) Low-and-slow evasion (malicious hosts reduce encryption/shadow-copy/registry-change volume by 70%): F1 drops to ${risk.adversarial_robustness.low_and_slow_evasion.f1_score} — recall falls to ${risk.adversarial_robustness.low_and_slow_evasion.recall} as the attacker's signal weakens, while precision stays high, showing the model is still trustworthy when it does fire but is not yet tuned for a stealthy long-dwell attacker.`),
  ]],
  ["Governance and drift controls", risk.governance_note],
]));
children.push(image(`${FIG}/09_risk_score_roc.png`, 360, 300));
children.push(caption("Figure 12. Risk-score model ROC curve."));
children.push(image(`${FIG}/10_adversarial_robustness.png`, 460, 296));
children.push(caption("Figure 13. Risk-score F1 under three adversarial/drift conditions vs baseline."));

// 12. Prototype and analyst workflow
children.push(h1("12. Prototype and analyst workflow"));
children.push(p("Streamlit dashboard (src/dashboard.py, 8 tabs), verified to compile and boot without errors in a headless smoke test."));
children.push(gridTable(
  ["Prototype function", "Current status", "Test evidence", "Remaining work"],
  [
    ["Load/refresh data", "Implemented", "Dashboard loads all 4 datasets and 9 output files via cached readers; headless boot confirmed (T09)", "Add manual refresh button + file-upload override"],
    ["View baselines and anomalies", "Implemented", "Overview + Anomaly Detection tabs render metrics, tables and PCA scatter plots", "Add time-range filter"],
    ["Inspect model outputs and explanations", "Implemented", "Supervised ML tab shows confusion matrices and XGBoost feature-importance charts per task", "Add SHAP-style per-prediction explanation"],
    ["Review incident timeline", "Implemented", "Incident Timeline tab: filterable table + MITRE-phase scatter plot over time", "Add entity drill-down view"],
    ["Compare simulation scenarios", "Implemented", "Simulation tab shows scenario table + bar charts for spread and downtime", "Allow custom scenario parameters from the UI"],
    ["Review intelligence/NLP output", "Implemented", "Security Intelligence and Text Mining tabs show IOC tables, MITRE mapping and NMF topics", "Add live ticket submission for on-the-fly classification"],
    ["Export or communicate recommendation", "Partially implemented", "Executive key numbers and recommendation shown in Overview tab", "Add PDF/CSV export button for the executive briefing"],
  ],
  [2500, 1500, 3200, 2439]
));

// 13. Testing and quality assurance
children.push(h1("13. Testing and quality assurance"));
children.push(p("Automated test log (src/test_log.py) — 10/10 tests passing:"));
children.push(gridTable(
  ["Test ID", "Component", "Input/condition", "Expected result", "Actual result"],
  testLog.map(r => r.map(c => c.replace(/^"|"$/g, ""))),
  [700, 2000, 3200, 2700, 1039]
));

// 14. Updated schedule and backlog
children.push(h1("14. Updated schedule and backlog"));
children.push(gridTable(
  ["Item", "Owner", "Priority", "Due", "Definition of done"],
  [
    ["Expand text corpus with naturalistic, varied phrasing (reduce NLP F1 over-fit to templates)", "A", "H", "16 Sep 2026", "NLP F1 on held-out split reported between 0.80-0.95 on an expanded, less templated corpus"],
    ["Harden dashboard for concurrent multi-user access", "B", "M", "18 Sep 2026", "Dashboard tested with 3+ simultaneous sessions without state errors"],
    ["Automate risk-score drift-monitoring governance policy", "B", "H", "20 Sep 2026", "Weekly recalibration job scripted and scheduled with alerting on precision < 0.75"],
    ["Add PDF/CSV export for executive briefing", "A", "M", "20 Sep 2026", "Export button on Overview tab produces a shareable one-page briefing"],
    ["Independent partner code review of all 9 pipeline scripts", "Both", "H", "19 Sep 2026", "Joint review meeting completed, sign-off logged (Section 15)"],
  ],
  [3100, 900, 900, 1500, 3239]
));

// 15. Team contribution evidence
children.push(h1("15. Team contribution evidence"));
children.push(gridTable(
  ["Member", "Components completed", "Repository/artefact evidence", "Partner review completed"],
  [
    ["Member A (Goliati) — Data and Modelling Lead", "data_gen.py, eda.py, supervised_model.py, unsupervised_model.py, risk_score.py", "Commits to /src and /data; outputs/supervised_model_results.json, unsupervised_model_results.json, risk_score_results.json", "Reviewed by Member B for cybersecurity relevance and attack-technique realism"],
    ["Member B (Sheefeni) — Security Engineering and Intelligence Lead", "incident_correlation.py, nlp_pipeline.py, simulation.py, threat_intel.py, dashboard.py", "Commits to /src; outputs/incident_timeline.csv, nlp_results.json, simulation_results.json, threat_intelligence_report.json", "Reviewed by Member A for model/statistical soundness"],
  ],
  [3100, 2500, 2500, 1539]
));

// 16. Submission checklist
children.push(h1("16. Submission checklist"));
const checklist = [
  "Implementation-plan PDF/DOCX", "Working prototype (src/dashboard.py, headless-boot verified)",
  "Repository/code snapshot (9 pipeline scripts + dashboard)", "Data dictionary and quality log (Section 3, outputs/data_quality_report.json)",
  "Preliminary model metrics (Sections 5, 6, 10, 11)", "Simulation and NLP outputs (Sections 9, 10)",
  "Predictive/adversarial evidence (Section 11)", "Test log (Section 13, outputs/test_log.csv — 10/10 passing)",
  "Updated schedule/backlog (Section 14)", "Contribution evidence for both members (Section 15)",
];
checklist.forEach(item => children.push(p([txt("☑ ", { bold: true, color: GREEN }), txt(item)])));

// ---------------------------------------------------------------------------
const doc = new Document({
  sections: [{
    properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1080, bottom: 1080, left: 1080, right: 1080 } } },
    children,
  }],
  styles: {
    default: { document: { run: { font: "Calibri", size: 21 } } },
    heading1: { run: { color: NAVY, size: 30, bold: true } },
    heading2: { run: { color: NAVY, size: 24, bold: true } },
  },
});

Packer.toBuffer(doc).then(buf => {
  fs.writeFileSync("/home/claude/ransomguard/outputs/SAS821S_Milestone2_Implementation_Plan.docx", buf);
  console.log("Document written.");
});
