"""Hypothesis H2: does the fail-open gate lose fewer real vulnerabilities than trusting the model's verdict alone?

Re-scores one saved run three ways (no new model calls):
  verdict alone       hide an alert whenever the model says likely_false_positive
  verdict + conf      ... and its confidence is at least the threshold
  full gate           ... and its evidence was verified (what the tool really does)

Usage: python scripts/compare_gate.py data/splits/dev.csv CWE-502 [run_id] [threshold]
"""
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # so "codereview" imports from the project folder

from codereview import evaluate, store
from codereview.config import Config

truth_path, cwe = sys.argv[1], sys.argv[2]
runs_dir = Config().runs_dir
run_id = sys.argv[3] if len(sys.argv) > 3 else store.latest_run(runs_dir)
threshold = float(sys.argv[4]) if len(sys.argv) > 4 else 0.8
truth = evaluate.load_truth(truth_path, [cwe])

rules = {
    "verdict alone": lambda v, ok: v.get("verdict") == "likely_false_positive",
    "verdict + conf": lambda v, ok: v.get("verdict") == "likely_false_positive" and (v.get("confidence_score") or 0) >= threshold,
    "full gate": lambda v, ok: v.get("verdict") == "likely_false_positive" and (v.get("confidence_score") or 0) >= threshold and ok,
}
hidden = {name: defaultdict(list) for name in rules}  # key -> one True/False per alert
for r in store.load_run(runs_dir, run_id):
    f, v = r["finding"], r["verdict"] or {}
    key = evaluate._key(f["file"], f["cwe"] or "")
    if key not in truth:
        continue
    for name, rule in rules.items():
        hidden[name][key].append(rule(v, bool(r["verified"])))

real = sum(1 for k in hidden["full gate"] if truth[k])
false = sum(1 for k in hidden["full gate"] if not truth[k])
print(f"Run {run_id}, {cwe}, threshold {threshold}: {real} real files, {false} false-alarm files")
for name in rules:
    gone = [k for k, h in hidden[name].items() if all(h)]  # a file is hidden only if ALL its alerts are hidden
    removed = sum(1 for k in gone if not truth[k])
    lost = sum(1 for k in gone if truth[k])
    print(f"  {name:15} false alarms removed {removed}/{false}   real lost {lost}/{real}")