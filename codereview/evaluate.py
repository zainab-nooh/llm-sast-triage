"""Score a run against benchmark truth, and sweep the confidence threshold on stored verdicts (no new model calls).

Two truth formats are accepted:
  1. Our own CSV:            file,cwe,real_vulnerability          (real_vulnerability = true or false)
  2. OWASP Benchmark's file: expectedresults-0.1.csv              (test name, category, real vulnerability, cwe)
A truth row counts as 'flagged' when at least one finding in the same file (matched by file name without
extension) has the same CWE. This is how the OWASP Benchmark scores tools too: one verdict per test case.
"""
import csv
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import gate, store
from .models import Verdict


# The benchmark sometimes uses a more specific or more general CWE than the scanners for the same weakness.
# Scanner CWE -> benchmark CWE. Only used when scoring, so the alerts and the report keep the scanner's CWE.
SCORING_ALIASES = {
    "CWE-95": "CWE-94",    # eval/exec: scanners say CWE-95 (eval injection), the benchmark says CWE-94 (code injection)
    "CWE-327": "CWE-328",  # MD5/SHA-1: scanners say CWE-327 (broken crypto), the benchmark says CWE-328 (weak hash)
}


def _key(file: str, cwe: str) -> Tuple[str, str]:
    return Path(file).stem, SCORING_ALIASES.get(cwe, cwe)


def load_truth(path: str, cwes: Optional[List[str]] = None) -> Dict[Tuple[str, str], bool]:
    """Read truth; with cwes, keep only those weakness types (for example the 6 you chose)."""
    truth = {}
    with open(path, newline="") as f:
        first = f.readline()
        f.seek(0)
        if first.startswith("# test name"):                       # OWASP Benchmark expectedresults file
            for row in csv.reader(f):
                if row and not row[0].startswith("#"):
                    truth[_key(row[0].strip(), f"CWE-{row[3].strip()}")] = row[2].strip().lower() == "true"
        else:
            for row in csv.DictReader(f):
                truth[_key(row["file"], row["cwe"])] = row["real_vulnerability"].strip().lower() == "true"
    if cwes:
        wanted = {SCORING_ALIASES.get(c, c) for c in cwes}
        truth = {k: v for k, v in truth.items() if k[1] in wanted}
    return truth


def fbeta(precision: float, recall: float, beta: float) -> float:
    d = beta * beta * precision + recall
    return (1 + beta * beta) * precision * recall / d if d else 0.0


def confusion(flagged: set, truth: Dict[Tuple[str, str], bool]) -> dict:
    tp = sum(1 for k, real in truth.items() if real and k in flagged)
    fp = sum(1 for k, real in truth.items() if not real and k in flagged)
    fn = sum(1 for k, real in truth.items() if real and k not in flagged)
    tn = sum(1 for k, real in truth.items() if not real and k not in flagged)
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(p, 3), "recall": round(r, 3),
            "f1": round(fbeta(p, r, 1), 3), "f2": round(fbeta(p, r, 2), 3)}


def evaluate_rows(rows: List[dict], truth: dict, threshold: float = None) -> dict:
    scanner_flagged, kept = set(), set()
    for r in rows:
        f = r["finding"]
        if not f.get("cwe"):
            continue
        k = _key(f["file"], f["cwe"])
        scanner_flagged.add(k)
        action = r["decision"]["action"]
        if threshold is not None and r["verdict"]:                      # re-run only the gate
            d = gate.decide(Verdict.model_validate(r["verdict"]), r["verified"], threshold)
            action = d.action
        if action == "keep":
            kept.add(k)
    a, c = confusion(scanner_flagged, truth), confusion(kept, truth)
    real_flagged = a["tp"]
    return {"scanner_only": a, "pipeline": c,
            "false_positives_removed": round(1 - c["fp"] / a["fp"], 3) if a["fp"] else None,
            "real_findings_lost": round((a["tp"] - c["tp"]) / real_flagged, 3) if real_flagged else None,
            "cost": round(sum(r["cost"] for r in rows), 4), "seconds": round(sum(r["seconds"] for r in rows), 1)}


def evaluate(runs_dir: str, run_id: str, truth_path: str, threshold: float = None,
             cwes: Optional[List[str]] = None) -> dict:
    return evaluate_rows(store.load_run(runs_dir, run_id), load_truth(truth_path, cwes), threshold)


def sweep(runs_dir: str, run_id: str, truth_path: str, thresholds=(0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 0.99),
          cwes: Optional[List[str]] = None) -> List[dict]:
    rows, truth = store.load_run(runs_dir, run_id), load_truth(truth_path, cwes)
    out = []
    for t in thresholds:
        e = evaluate_rows(rows, truth, t)
        out.append({"threshold": t, "false_positives_removed": e["false_positives_removed"],
                    "real_findings_lost": e["real_findings_lost"], "f1": e["pipeline"]["f1"], "f2": e["pipeline"]["f2"]})
    return out
