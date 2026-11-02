"""Step 10: running the tool in CI (GitHub Actions or any other pipeline).

`python -m codereview ci <folder>` scans, lets the AI check the alerts with the frozen settings
(context level 2, threshold 0.6, effort low), and writes:
- a SARIF file (for GitHub code scanning, or as a downloadable artifact),
- a Markdown summary (GitHub shows it on the run page),
- GitHub annotations, so Confirmed and Needs review alerts appear on the pull request's changed files.
The exit code lets the pipeline fail the check (see --fail-on).

Safety:
- Without an API key it falls back to scanner only: every alert is kept, nothing is hidden (fail-open).
- A spending limit (default US$1) stops the AI; alerts it did not reach are kept as "not checked".
- Code, file names and model text are untrusted, so they are escaped before going into Markdown or annotations.
"""
import json
import os
import re
from pathlib import Path
from typing import List, Optional

import tempfile

from . import pipeline, report, scanners, store
from .config import Config
from .report import CWES
from .server import CONTEXT_LEVEL, MODELS, THRESHOLD, group_of, sarif_for, to_issue

EFFORT = "low"          # frozen with the other evaluation settings
FAIL_ON = {"confirmed": {"Confirmed"}, "review": {"Confirmed", "Needs review"}, "never": set()}


def md(text, limit: int = 200) -> str:
    """Plain text for a Markdown table cell: one line, no links, images, HTML or table breaks."""
    s = re.sub(r"\s+", " ", str(text or "")).strip()[:limit]
    return re.sub(r"([\\`*_{}\[\]<>()#+!|~-])", r"\\\1", s)


def annotation(level: str, file: str, line: int, title: str, message: str) -> str:
    """A GitHub workflow command such as ::error file=app.py,line=3,title=...::message (values escaped)."""
    def data(s):
        return str(s).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")

    def prop(s):
        return data(s).replace(":", "%3A").replace(",", "%2C")
    return f"::{level} file={prop(file)},line={int(line)},title={prop(title)}::{data(message)}"


def choose_model(model: str) -> tuple:
    """'auto' = Claude Haiku when a key is set, otherwise scanner only (nothing hidden)."""
    has_key = bool(os.getenv("ANTHROPIC_API_KEY", "").strip())
    if model == "auto":
        model = "claude" if has_key else "scanner"
    if model in ("claude", "sonnet") and not has_key:
        raise ValueError(f"model '{model}' needs ANTHROPIC_API_KEY (add it as a repository secret)")
    if model == "scanner":
        return "scanner", None, None
    if model not in MODELS:
        raise ValueError(f"unknown model '{model}'; use auto, claude, sonnet, mock or scanner")
    provider, name = MODELS[model]
    return model, provider, name


def summary_md(issues: List[dict], run_id: str, model: str, spent: float, partial: Optional[str], limit: int = 50) -> str:
    groups = {g: [i for i in issues if i["group"] == g] for g in ("Confirmed", "Needs review", "Hidden")}
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    lines = ["## SAST Triage", "",
             f"Model: **{md(model)}** · context level {CONTEXT_LEVEL} · threshold {THRESHOLD} · AI cost ${spent:.4f} · run `{run_id}`", ""]
    if model == "scanner":
        lines += ["> No API key, so the AI did not check these alerts. Every alert is kept.", ""]
    if partial:
        lines += [f"> Partial scan: {md(partial)}. Alerts the AI did not reach are kept as Needs review.", ""]
    lines += ["| Confirmed | Needs review | Hidden as false alarms | Total |", "|---|---|---|---|",
              f"| {len(groups['Confirmed'])} | {len(groups['Needs review'])} | {len(groups['Hidden'])} | {len(issues)} |", ""]
    for g in ("Confirmed", "Needs review"):
        items = sorted(groups[g], key=lambda i: (sev.get(i["sev"], 9), i["file"], i["line"]))
        if not items:
            continue
        lines += [f"### {g} ({len(items)})", "", "| Severity | Weakness | Where | Why |", "|---|---|---|---|"]
        for i in items[:limit]:
            why = i["reason"] or i["decision"] or i["msg"]
            lines.append(f"| {i['sev']} | {md(i['cwe'])} | {md(i['file'], 120)}:{int(i['line'])} | {md(why)} |")
        if len(items) > limit:
            lines.append(f"| | | | ...and {len(items) - limit} more in the SARIF file |")
        lines.append("")
    if groups["Hidden"]:
        lines += ["<details><summary>Hidden as likely false alarms (" + str(len(groups["Hidden"])) + ")</summary>", "",
                  "| Weakness | Where | Why the AI thinks it is safe |", "|---|---|---|"]
        for i in groups["Hidden"][:limit]:
            lines.append(f"| {md(i['cwe'])} | {md(i['file'], 120)}:{int(i['line'])} | {md(i['reason'])} |")
        lines += ["", "</details>", ""]
    return "\n".join(lines)


def run_ci(target: str, model: str = "auto", cwes: Optional[List[str]] = None, max_cost: float = 1.0,
           sarif_out: str = "sast-triage.sarif", summary_out: Optional[str] = None, fail_on: str = "confirmed",
           annotate: bool = True, runs_dir: Optional[str] = None, echo=print) -> int:
    """Returns the exit code: 0 = pass, 1 = alerts matching --fail-on. Raises ValueError/RuntimeError (exit 2) on setup errors."""
    if fail_on not in FAIL_ON:
        raise ValueError("fail-on must be confirmed, review or never")
    label, provider, name = choose_model(model)
    cfg = Config(target=target, context_level=CONTEXT_LEVEL, threshold=THRESHOLD, only_cwes=cwes or list(CWES),
                 skip_judge=label == "scanner", effort=EFFORT)
    if runs_dir:
        cfg.runs_dir = runs_dir
    if provider:
        cfg.provider, cfg.model = provider, name

    # Run the scanners first: a missing or crashed scanner must fail the check, never pass it with 0 alerts
    scan_dir = Path(tempfile.mkdtemp(prefix="sast-triage-"))
    sarif_in, bandit_in = scanners.run_all(cfg, scan_dir)
    missing = [n for n, f in (("Semgrep", sarif_in), ("Bandit", bandit_in)) if not f]
    if missing:
        raise RuntimeError(f"{' and '.join(missing)} produced no results (not installed, or crashed: see the log above)")
    cfg.sarif_path, cfg.bandit_path = str(sarif_in), str(bandit_in)

    def should_stop(spent: float) -> Optional[str]:
        return f"spending limit of ${max_cost:.2f} reached" if max_cost is not None and spent >= max_cost else None

    run_id = pipeline.run(cfg, should_stop=should_stop)
    report.build(cfg.runs_dir, run_id)
    rows = store.load_run(cfg.runs_dir, run_id)
    # Paths relative to the repository root, so GitHub can place them on the right file
    prefix = Path(target).as_posix().rstrip("/")
    prefix = "" if prefix in (".", "") else prefix[2:] if prefix.startswith("./") else prefix
    issues = [to_issue(run_id, "", r, None) for r in rows]
    for i in issues:
        i["file"] = f"{prefix}/{i['file']}" if prefix else i["file"]
    spent = sum(r["cost"] or 0 for r in rows)
    partial = store.partial_reason(cfg.runs_dir, run_id)

    sarif = sarif_for(issues)
    Path(sarif_out).write_text(json.dumps(sarif, indent=1), encoding="utf-8")
    text = summary_md(issues, run_id, label if label == "scanner" else name, spent, partial)
    if summary_out:
        with open(summary_out, "a", encoding="utf-8") as f:
            f.write(text + "\n")
    if annotate:
        for i in issues:
            if i["group"] == "Hidden":
                continue
            level = "error" if i["group"] == "Confirmed" else "warning"
            echo(annotation(level, i["file"], i["line"], f"{i['group']}: {i['cwe']} {i['rule']}",
                            (i["reason"] or i["msg"])[:500]))
    counts = {g: sum(i["group"] == g for i in issues) for g in ("Confirmed", "Needs review", "Hidden")}
    echo(f"SAST Triage: {counts['Confirmed']} confirmed, {counts['Needs review']} need review, "
         f"{counts['Hidden']} hidden, AI cost ${spent:.4f}. SARIF: {sarif_out}")
    failing = [i for i in issues if i["group"] in FAIL_ON[fail_on]]
    if failing:
        echo(f"Failing because of {len(failing)} alert(s) (--fail-on {fail_on}).")
        return 1
    return 0
