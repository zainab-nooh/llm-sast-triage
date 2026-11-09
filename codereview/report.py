"""Step 9: HTML report from stored results. Same look as the web app (Terracotta, light and dark), one self-contained file."""
import base64
import re
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from . import policy, store
from .config import Config

HERE = Path(__file__).parent
# Weakness types the tool judges: name and severity (shared with the web app)
CWES = {"CWE-89": ("SQL injection", "high"), "CWE-78": ("OS command injection", "high"),
        "CWE-95": ("Code injection", "critical"), "CWE-502": ("Unsafe deserialization", "critical"),
        "CWE-611": ("XML external entities", "high"), "CWE-614": ("Cookie without Secure flag", "medium")}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
GENERIC = {"src", "web", "app", "lib", "code", "python"}   # folder names that say nothing about the project
GROUPS = [("confirmed", "Confirmed by AI", "The model traced untrusted input to the flagged line. Fix these first."),
          ("uncertain", "Needs review", "The model could not prove these safe or unsafe. A person should decide."),
          ("scanner_only", "Not checked by the AI",
           "No AI judgement: the weakness type has no policy rule, or the scan stopped before reaching them. Kept for a person."),
          ("suppressed", "Hidden as likely false positives",
           "Hidden from the main list because the model was confident they are safe. Listed here so they can be audited.")]
LABELS = {"real": "Real", "fp": "False alarm", "unsure": "Unsure"}


def project_name(target: str) -> str:
    p = Path(str(target).replace("\\", "/"))
    if p.name.lower() in GENERIC and p.parent.name:
        return f"{p.parent.name}/{p.name}"
    return p.name or str(target)


def _logo(name: str) -> str:
    f = HERE / "web" / name
    return "data:image/png;base64," + base64.b64encode(f.read_bytes()).decode() if f.exists() else ""


def _lines(spec) -> set:
    """'270-271' or '62' or '27-29,40' -> set of line numbers."""
    out = set()
    for a, b in re.findall(r"(\d+)(?:\s*-\s*(\d+))?", str(spec)):
        a, b = int(a), int(b or a)
        if b - a < 500:
            out.update(range(a, b + 1))
    return out


def _norm(path: str) -> str:
    return str(path).replace("\\", "/").lstrip("./")


def _item(row: dict, review, owasp: dict) -> dict:
    f, v = row["finding"], row["verdict"] or {}
    cwe = f.get("cwe") or ""
    name, sev = CWES.get(cwe, ("Other", "medium"))
    flagged = set(range(f["start_line"], (f.get("end_line") or f["start_line"]) + 1))
    cited = set()
    for e in v.get("evidence", []):
        if _norm(e.get("file", "")).endswith(_norm(f["file"])) or _norm(f["file"]).endswith(_norm(e.get("file", ""))):
            cited |= _lines(e.get("lines", ""))
    conf = v.get("confidence_score")
    return {"f": f, "v": v, "cwe": cwe or "no CWE", "name": name, "sev": sev, "owasp": owasp.get(cwe, ""),
            "rule": f["rule_id"].split(".")[-1], "decision": row["decision"]["reason"],
            "conf": conf, "conf_pct": int(round((conf or 0) * 100)), "code": (row["context"] or {}).get("lines", []),
            "flagged": flagged, "cited": cited - flagged, "review": review,
            "review_label": LABELS.get((review or {}).get("label", ""), "")}


def build(runs_dir: str, run_id: str) -> Path:
    rows = store.load_run(runs_dir, run_id)
    config = store.load_config(runs_dir, run_id)
    reviews = store.load_reviews(runs_dir, run_id)
    try:
        owasp = {c: r.get("owasp", "") for c, r in policy.load_policy(config.get("policy_path") or Config().policy_path).items()}
    except OSError:
        owasp = {}
    groups = {k: [] for k, _, _ in GROUPS}
    by_cwe = {}
    for r in rows:
        if r["verdict"] is None and r["decision"]["action"] != "suppress":
            key = "scanner_only"
        elif r["decision"]["action"] == "suppress":
            key = "suppressed"
        elif r["verdict"]["verdict"] == "confirmed":
            key = "confirmed"
        else:
            key = "uncertain"
        it = _item(r, reviews.get(r["finding"]["id"]), owasp)
        groups[key].append(it)
        c = by_cwe.setdefault(it["cwe"], {"name": it["name"], "sev": it["sev"], "owasp": it["owasp"],
                                          "total": 0, "confirmed": 0, "uncertain": 0, "scanner_only": 0, "suppressed": 0})
        c["total"] += 1
        c[key] += 1
    for items in groups.values():
        items.sort(key=lambda i: (SEV_ORDER.get(i["sev"], 9), i["f"]["file"], i["f"]["start_line"]))
    total = len(rows)
    cost = sum(r["cost"] or 0 for r in rows)
    seconds = sum(r["seconds"] or 0 for r in rows)
    env = Environment(loader=FileSystemLoader(HERE / "templates"), autoescape=True)  # always escape: code and model text are untrusted
    html = env.get_template("report.html.j2").render(
        run_id=run_id, groups=groups, group_info=GROUPS, total=total, config=config,
        project=project_name(config.get("target", "")), by_cwe=sorted(by_cwe.items(), key=lambda kv: (SEV_ORDER.get(kv[1]["sev"], 9), kv[0])),
        hidden_pct=round(100 * len(groups["suppressed"]) / total) if total else 0,
        reviewed=sum(1 for g in groups.values() for i in g if i["review"]),
        cost=cost, seconds=seconds, partial=store.partial_reason(runs_dir, run_id), generated=datetime.now().strftime("%d %b %Y, %H:%M"),
        logo_main=_logo("logo-main.png"), logo_by=_logo("logo-by.png"))
    out = Path(runs_dir) / run_id / "report.html"
    out.parent.mkdir(parents=True, exist_ok=True)   # the scan's folder may be missing (results copied, or the demo data)
    out.write_text(html, encoding="utf-8")  # utf-8, or Windows fails on characters like emoji in model text
    return out
