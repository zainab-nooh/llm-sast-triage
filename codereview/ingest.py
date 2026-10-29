"""Step 2: turn Semgrep SARIF and Bandit JSON into one Finding format."""
import json
import re
from pathlib import Path
from typing import List, Optional

from .models import Finding

CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.I)


# Bandit labels some rules with a CWE that does not describe the real weakness.
# We correct them so each alert gets the right rubric, and keep the original in Finding.scanner_cwe.
# Checked against Bandit 1.9 output on the OWASP Benchmark for Python (October 2026).
BANDIT_CWE_FIX = {
    "B102": "CWE-95",   # exec used: Bandit says CWE-78 (OS command), it is code injection
    "B307": "CWE-95",   # eval used: same
    "B201": "CWE-489",  # Flask debug=True: Bandit says CWE-94 (code injection), it is active debug code (a setting)
    "B506": "CWE-502",  # yaml.load: Bandit says CWE-20 (input validation), it is unsafe deserialization
    **{r: "CWE-611" for r in ("B313", "B314", "B315", "B316", "B317", "B318", "B319", "B320",
                               "B405", "B406", "B407", "B408", "B409", "B410", "B411")},  # XML parsing: Bandit says CWE-20
}

# Some Semgrep community rules carry a wrong CWE in their metadata (keyed by the last part of the rule id).
# Example: the Django and Flask "tainted-sql-string" rules are tagged CWE-915 and CWE-704.
SEMGREP_CWE_FIX = {
    "tainted-sql-string": "CWE-89",
}


def norm_cwe(text) -> Optional[str]:
    m = CWE_RE.search(str(text or ""))
    return f"CWE-{m.group(1)}" if m else None


def _rel(path: str, root: str) -> str:
    """Make a scanner path relative to the scanned folder, whatever folder the scanner was run from."""
    path = path.replace("file://", "")
    rootp = Path(root).resolve()
    p = Path(path)
    if p.is_absolute():
        try:
            return str(p.resolve().relative_to(rootp))
        except ValueError:
            pass
    parts = p.parts
    for i in range(len(parts)):
        cand = Path(*parts[i:])
        if not cand.is_absolute() and (rootp / cand).exists():
            return str(cand)
    return path


def parse_sarif(path: Path, root: str) -> List[Finding]:
    data = json.loads(Path(path).read_text())
    findings: List[Finding] = []
    for run in data.get("runs", []):
        rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            rule_id = res.get("ruleId", "unknown")
            rule = rules.get(rule_id, {})
            tags = " ".join(rule.get("properties", {}).get("tags", []))
            cwe = norm_cwe(tags) or norm_cwe(rule.get("shortDescription", {}).get("text")) \
                or norm_cwe(rule.get("fullDescription", {}).get("text"))
            scanner_cwe = cwe
            cwe = SEMGREP_CWE_FIX.get(rule_id.split(".")[-1], cwe)
            loc = res["locations"][0]["physicalLocation"]
            region = loc.get("region", {})
            file = _rel(loc["artifactLocation"]["uri"], root)
            trace: List[str] = []
            for flow in res.get("codeFlows", []):
                for tf in flow.get("threadFlows", []):
                    for step in tf.get("locations", []):
                        pl = step.get("location", {}).get("physicalLocation", {})
                        if pl:
                            trace.append(f"{_rel(pl['artifactLocation']['uri'], root)}:{pl.get('region', {}).get('startLine', 0)}")
            start = int(region.get("startLine", 1))
            findings.append(Finding(
                id=f"semgrep:{rule_id.split('.')[-1]}:{file}:{start}", tool="semgrep", rule_id=rule_id, cwe=cwe,
                scanner_cwe=scanner_cwe, file=file, start_line=start, end_line=int(region.get("endLine", start)),
                message=res.get("message", {}).get("text", ""), severity=res.get("level", "unknown"), trace=trace))
    return findings


def parse_bandit(path: Path, root: str) -> List[Finding]:
    data = json.loads(Path(path).read_text())
    findings: List[Finding] = []
    for r in data.get("results", []):
        file = _rel(r["filename"], root)
        lines = r.get("line_range") or [r["line_number"]]
        cwe_info = r.get("issue_cwe") or {}
        scanner_cwe = f"CWE-{cwe_info['id']}" if cwe_info.get("id") else None
        cwe = BANDIT_CWE_FIX.get(r["test_id"], scanner_cwe)
        findings.append(Finding(
            id=f"bandit:{r['test_id']}:{file}:{r['line_number']}", tool="bandit", rule_id=r["test_id"], cwe=cwe,
            scanner_cwe=scanner_cwe,
            file=file, start_line=min(lines), end_line=max(lines), message=r.get("issue_text", ""),
            severity=str(r.get("issue_severity", "unknown")).lower()))
    return findings


# Bandit's B4xx rules only say "this module was imported" and point at the import line, not at a use.
# The B3xx and B6xx rules flag the actual call, so judging the import line too would cost money and add nothing.
IMPORT_ONLY_RULES = {f"B{n}" for n in range(401, 416)}


def merge_duplicates(findings: List[Finding]) -> List[Finding]:
    """One alert per (file, line, CWE). Semgrep and Bandit often flag the same line, and Semgrep has
    near-identical rules (for example a Django and a Flask version). Judging each copy would cost
    money and count the same problem twice, so the copies are merged and remembered in also_reported_by."""
    merged: dict = {}
    for f in findings:
        key = (f.file, f.start_line, f.cwe)
        if key in merged:
            merged[key].also_reported_by.append(f"{f.tool}:{f.rule_id}")
        else:
            merged[key] = f
    return list(merged.values())


def parse_all(sarif: Optional[Path], bandit: Optional[Path], root: str,
              security_only: bool = True, only_cwes: Optional[List[str]] = None) -> List[Finding]:
    """Read both scanners' output into one list of alerts.

    security_only: drop alerts with no CWE (code-quality rules such as "useless inner function")
                   and Bandit's import-only alerts.
    only_cwes: keep only these CWEs, for example ["CWE-89"] for the prototype.
    """
    out: List[Finding] = []
    if sarif and Path(sarif).exists():
        out += parse_sarif(Path(sarif), root)
    if bandit and Path(bandit).exists():
        out += parse_bandit(Path(bandit), root)
    if security_only:
        out = [f for f in out if f.cwe and not (f.tool == "bandit" and f.rule_id in IMPORT_ONLY_RULES)]
    if only_cwes:
        out = [f for f in out if f.cwe in only_cwes]
    return merge_duplicates(out)
