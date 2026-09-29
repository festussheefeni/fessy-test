import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

FIG = "/home/claude/ransomguard/figures"

IMPLEMENTED = "#c8e6c9"   # green
PARTIAL = "#fff9c4"       # yellow
BORDER_IMPL = "#2e7d32"
BORDER_PART = "#f9a825"

fig, ax = plt.subplots(figsize=(13, 7.5))
ax.set_xlim(0, 13); ax.set_ylim(0, 7.5); ax.axis("off")


def box(x, y, w, h, text, fill, border, fontsize=8.3):
    b = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08",
                        linewidth=1.4, edgecolor=border, facecolor=fill)
    ax.add_patch(b)
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fontsize, wrap=True)


def arrow(p1, p2):
    a = FancyArrowPatch(p1, p2, arrowstyle="-|>", mutation_scale=12, color="#555", linewidth=1.1)
    ax.add_patch(a)


# Sources
sources = ["Email gateway\n(phishing)\n1,500 rows", "Endpoint/EDR\ntelemetry\n2,000 rows",
           "Identity/network\n/backup logs\n2,500 rows", "SOC tickets /\nthreat-intel text\n300 rows"]
for i, s in enumerate(sources):
    box(0.2, 6.0 - i * 1.55, 2.0, 1.2, s, IMPLEMENTED, BORDER_IMPL)

box(2.7, 3.2, 1.7, 1.8, "Ingestion &\npreparation\n(pandas ETL,\nfeature\nengineering)", IMPLEMENTED, BORDER_IMPL)
for i in range(4):
    arrow((2.2, 6.6 - i * 1.55), (2.7, 4.1))

# Analytical modules
modules = [
    ("Supervised ML\nXGBoost + LR\n(phishing, endpoint)\nF1 0.93-0.97", 5.0, 6.1),
    ("Unsupervised/UBA\nIsolation Forest +\nDBSCAN", 5.0, 4.55),
    ("NLP\nTF-IDF + NMF\ntopic modelling", 5.0, 3.0),
    ("Simulation\nNetworkX propagation,\n200 MC runs x4 scenarios", 5.0, 1.45),
]
for text, x, y in modules:
    box(x, y, 2.3, 1.35, text, IMPLEMENTED, BORDER_IMPL)
    arrow((4.4, 4.1), (x, y + 0.65))

box(5.0, -0.15, 2.3, 1.35, "Predictive/adversarial\nrisk score\n(GBM, robustness tests)", PARTIAL, BORDER_PART)
arrow((4.4, 4.1), (5.0, 0.4))

# Investigation & intelligence layer
box(7.8, 3.5, 2.1, 2.6, "Security investigation\n& intelligence\nIncident timeline\n(1,240 events),\nMITRE ATT&CK\nmapping, IOC list", IMPLEMENTED, BORDER_IMPL)
for text, x, y in modules:
    arrow((x + 2.3, y + 0.65), (7.8, 4.8))
arrow((7.3, 0.55), (7.8, 4.0))

# Outputs
box(10.4, 4.7, 2.3, 1.4, "Decision-support\ndashboard\n(Streamlit, 8 tabs)", IMPLEMENTED, BORDER_IMPL)
box(10.4, 2.5, 2.3, 1.4, "Executive risk\nbriefing &\nrecovery prioritisation", IMPLEMENTED, BORDER_IMPL)
arrow((9.9, 4.9), (10.4, 5.3))
arrow((9.9, 4.4), (10.4, 3.1))

# Legend
leg1 = mpatches.Patch(facecolor=IMPLEMENTED, edgecolor=BORDER_IMPL, label="Implemented (Milestone 2)")
leg2 = mpatches.Patch(facecolor=PARTIAL, edgecolor=BORDER_PART, label="Partially implemented — governance/drift monitoring deferred to Milestone 3")
ax.legend(handles=[leg1, leg2], loc="lower center", bbox_to_anchor=(0.5, -0.05), ncol=2, fontsize=8.5, frameon=False)

ax.set_title("RansomGuard — implemented architecture and data flow (Milestone 2)", fontsize=12, fontweight="bold")
plt.tight_layout()
plt.savefig(f"{FIG}/00_updated_architecture.png", dpi=140, bbox_inches="tight")
print("saved")
