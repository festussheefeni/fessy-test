"""
Ransomware propagation simulation on the simulated hospital host/network
graph. Compares a baseline (no additional controls) scenario against
control scenarios: (1) network segmentation, (2) early EDR isolation
triggered by the supervised model / risk score, (3) both combined.
Monte-Carlo iterations quantify sensitivity of downtime impact.
"""
import json
import random
import sys
sys.path.insert(0, "/home/claude/ransomguard/src")

import numpy as np
import pandas as pd
import networkx as nx
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

DATA = "/home/claude/ransomguard/data"
OUT = "/home/claude/ransomguard/outputs"
FIG = "/home/claude/ransomguard/figures"
SEED = 42
random.seed(SEED)
np.random.seed(SEED)

hosts = pd.read_csv(f"{DATA}/hosts_reference.csv")
N_HOSTS = len(hosts)
DEPARTMENTS = hosts.department.unique().tolist()

# ---------------------------------------------------------------------------
# Build a plausible flat-ish hospital network graph:
# hosts connect within department (high prob) and across departments via a
# handful of shared services (file/backup/DC), representing typical weak
# segmentation in legacy hospital networks.
# ---------------------------------------------------------------------------
def build_network(segmented=False):
    G = nx.Graph()
    for _, h in hosts.iterrows():
        G.add_node(h.host_id, department=h.department, role=h.role)
    dept_groups = hosts.groupby("department").host_id.apply(list).to_dict()
    # dense intra-department connectivity
    for dept, members in dept_groups.items():
        for i in range(len(members)):
            for j in range(i + 1, len(members)):
                if random.random() < 0.55:
                    G.add_edge(members[i], members[j])
    # cross-department connectivity via shared servers (file/backup/DC)
    shared = hosts[hosts.role.isin(["file_server", "backup_server", "domain_controller"])].host_id.tolist()
    all_hosts = hosts.host_id.tolist()
    cross_prob = 0.02 if segmented else 0.12
    for hnode in all_hosts:
        for s in shared:
            if hnode != s and random.random() < cross_prob:
                G.add_edge(hnode, s)
    # segmentation scenario also removes ~60% of any remaining cross-dept direct edges
    if segmented:
        cross_edges = [(u, v) for u, v in G.edges()
                        if G.nodes[u]["department"] != G.nodes[v]["department"]]
        for u, v in cross_edges:
            if random.random() < 0.6:
                G.remove_edge(u, v)
    return G


def simulate_propagation(G, patient_zero, edr_isolation=False, detection_delay_hours=0,
                          max_hours=96, base_infect_prob=0.35):
    """
    Discrete-time SIR-like propagation over hourly steps.
    edr_isolation: if True, an infected host is isolated (edges cut) after
    `detection_delay_hours` from its own infection time, stopping further spread from it.
    """
    infected_time = {patient_zero: 0}
    infected = {patient_zero}
    isolated = set()
    G = G.copy()
    for hour in range(1, max_hours + 1):
        newly_infected = set()
        for node in list(infected):
            if node in isolated:
                continue
            if edr_isolation and (hour - infected_time[node]) >= detection_delay_hours:
                isolated.add(node)
                continue
            for nbr in G.neighbors(node):
                if nbr not in infected and random.random() < base_infect_prob / 24:  # hourly-adjusted prob
                    newly_infected.add(nbr)
        for n in newly_infected:
            infected.add(n)
            infected_time[n] = hour
        if len(infected) >= len(G.nodes):
            break
    downtime_hours_per_host = 8  # avg clinical-system recovery/downtime per infected host
    return {
        "n_infected": len(infected),
        "pct_infected": round(100 * len(infected) / len(G.nodes), 2),
        "n_isolated_before_full_encrypt": len(isolated),
        "estimated_downtime_hours": len(infected) * downtime_hours_per_host,
        "infected_hosts": sorted(infected),
    }


SCENARIOS = {
    "baseline_no_controls": dict(segmented=False, edr_isolation=False, detection_delay_hours=None),
    "network_segmentation_only": dict(segmented=True, edr_isolation=False, detection_delay_hours=None),
    "early_edr_isolation_only": dict(segmented=False, edr_isolation=True, detection_delay_hours=6),
    "segmentation_plus_early_edr": dict(segmented=True, edr_isolation=True, detection_delay_hours=6),
}

N_ITER = 200
results = {}
for scen_name, params in SCENARIOS.items():
    outcomes = []
    for it in range(N_ITER):
        G = build_network(segmented=params["segmented"])
        patient_zero = random.choice(hosts.host_id.tolist())
        r = simulate_propagation(G, patient_zero,
                                  edr_isolation=params["edr_isolation"],
                                  detection_delay_hours=params["detection_delay_hours"] or 0)
        outcomes.append(r)
    pct = np.array([o["pct_infected"] for o in outcomes])
    downtime = np.array([o["estimated_downtime_hours"] for o in outcomes])
    results[scen_name] = {
        "n_iterations": N_ITER,
        "mean_pct_infected": round(float(pct.mean()), 2),
        "median_pct_infected": round(float(np.median(pct)), 2),
        "p90_pct_infected": round(float(np.percentile(pct, 90)), 2),
        "std_pct_infected": round(float(pct.std()), 2),
        "mean_downtime_hours": round(float(downtime.mean()), 1),
        "p90_downtime_hours": round(float(np.percentile(downtime, 90)), 1),
    }

with open(f"{OUT}/simulation_results.json", "w") as f:
    json.dump(results, f, indent=2)

# ---------------------------------------------------------------------------
# Comparative plot
# ---------------------------------------------------------------------------
fig, axes = plt.subplots(1, 2, figsize=(11, 4.3))
names = list(results.keys())
mean_pct = [results[n]["mean_pct_infected"] for n in names]
p90_pct = [results[n]["p90_pct_infected"] for n in names]
axes[0].bar(range(len(names)), mean_pct, color="#1f77b4", label="mean % infected")
axes[0].plot(range(len(names)), p90_pct, "ro--", label="p90 % infected")
axes[0].set_xticks(range(len(names))); axes[0].set_xticklabels(names, rotation=30, ha="right", fontsize=8)
axes[0].set_title("Infection spread by control scenario (200 Monte-Carlo runs)")
axes[0].legend(fontsize=8)

mean_dt = [results[n]["mean_downtime_hours"] for n in names]
axes[1].bar(range(len(names)), mean_dt, color="#d62728")
axes[1].set_xticks(range(len(names))); axes[1].set_xticklabels(names, rotation=30, ha="right", fontsize=8)
axes[1].set_title("Mean estimated clinical-system downtime (hours)")
plt.tight_layout()
plt.savefig(f"{FIG}/08_simulation_scenario_comparison.png", dpi=130)
plt.close()

print(json.dumps(results, indent=2))
