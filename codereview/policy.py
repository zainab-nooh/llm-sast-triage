"""Policy rules and CWE micro-rubrics. Add a new CWE by adding rubrics/cwe_<number>.yaml."""
from pathlib import Path
from typing import Dict, Optional

import yaml

GENERIC = {
    "id": "GENERIC", "title": "General secure coding review", "owasp": "",
    "rubric": [
        "Decide whether untrusted input can reach the flagged operation without being checked.",
        "A check that aborts on bad input (validation) protects the code after it.",
        "Changing a local copy of a value (sanitization) may not protect the original.",
        "If the code shown is not enough to decide, answer uncertain."],
    "examples": [],
}


def load_policy(path: str) -> Dict[str, dict]:
    data = yaml.safe_load(Path(path).read_text())
    return {r["cwe"]: r for r in data.get("rules", [])}


def for_cwe(cwe: Optional[str], policy_path: str, rubrics_dir: str) -> dict:
    """Return policy rule + micro-rubric for a CWE, or a generic rubric when none exists."""
    out = dict(GENERIC, known=False)   # known: this CWE has its own policy rule or rubric
    if not cwe:
        return out
    pol = load_policy(policy_path).get(cwe)
    if pol:
        out["known"] = True
        out.update({"id": pol["id"], "title": pol["title"], "owasp": pol.get("owasp", ""),
                "requirement": pol.get("requirement", "")})
    f = Path(rubrics_dir) / f"cwe_{cwe.replace('CWE-', '')}.yaml"
    if f.exists():
        r = yaml.safe_load(f.read_text())
        out["known"] = True
        out.update({"rubric": r.get("rubric", out["rubric"]), "examples": r.get("examples", [])})
        out.setdefault("id", r.get("id"))
    return out
