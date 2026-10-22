"""List the false alarms the pipeline still kept in a run, and why.

A benchmark file counts as a false alarm if ANY alert in it is kept, so every kept alert in a safe file is shown.
Usage: python scripts/why_kept.py data/benchmark-python/expectedresults-0.1.csv CWE-95 [run_id]
"""
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # so "codereview" imports from the project folder

from codereview import evaluate, store
from codereview.config import Config

truth_path, cwe = sys.argv[1], sys.argv[2]
runs_dir = Config().runs_dir
run_id = sys.argv[3] if len(sys.argv) > 3 else store.latest_run(runs_dir)
truth = evaluate.load_truth(truth_path, [cwe])
reasons = Counter()
for r in store.load_run(runs_dir, run_id):
    f, d, v = r["finding"], r["decision"], r["verdict"] or {}
    key = evaluate._key(f["file"], f["cwe"] or "")
    if key in truth and not truth[key] and d["action"] == "keep":
        print(f"{f['file']}:{f['start_line']}  {f['tool']}:{f['rule_id'].split('.')[-1]}")
        print(f"   verdict={v.get('verdict')} confidence={v.get('confidence_score')} verified={r['verified']}")
        print(f"   kept because: {d['reason']}")
        print(f"   AI said: {(v.get('reasoning') or '')[:220]}\n")
        reasons[v.get("verdict") if r["verified"] else "evidence rejected by verifier"] += 1
print(f"Run {run_id}: kept alerts in safe files, by cause: {dict(reasons)}")
