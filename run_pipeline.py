"""Run the full RansomGuard analytics pipeline end-to-end, in order."""
import subprocess
import sys

STEPS = [
    "data_gen.py",
    "eda.py",
    "supervised_model.py",
    "unsupervised_model.py",
    "incident_correlation.py",
    "nlp_pipeline.py",
    "simulation.py",
    "risk_score.py",
    "threat_intel.py",
]

if __name__ == "__main__":
    for step in STEPS:
        print(f"\n{'='*70}\nRunning {step}\n{'='*70}")
        result = subprocess.run([sys.executable, step], cwd="/home/claude/ransomguard/src")
        if result.returncode != 0:
            print(f"FAILED at {step}")
            sys.exit(1)
    print("\nPipeline complete. Launch dashboard with:\n  streamlit run src/dashboard.py")
