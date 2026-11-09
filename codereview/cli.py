"""Commands:  run, report, evaluate, sweep, inspect, serve, ci.   Example: python -m codereview run sample_target"""
import json
from pathlib import Path
from typing import List, Optional

import typer

from . import evaluate as ev
from . import ingest, pipeline, policy, prompts, report, slicer, store
from .config import Config

app = typer.Typer(help="Targeted LLM-assisted secure code review")


def _resolve(run_id: Optional[str], runs_dir: str) -> str:
    rid = run_id or store.latest_run(runs_dir)
    if not rid:
        raise typer.BadParameter("No runs found. Run `python -m codereview run <folder>` first.")
    return rid


@app.command()
def run(target: str,
        provider: str = typer.Option(None, help="mock | anthropic | openai | ollama"),
        model: str = typer.Option(None),
        context: int = typer.Option(2, help="1 function, 2 slice, 3 slice + helpers"),
        threshold: float = typer.Option(0.8),
        votes: int = typer.Option(1, help="3 for majority voting on final runs"),
        helpers: List[str] = typer.Option(None, help="folder with helper code the target calls, e.g. data/benchmark-python/helpers"),
        group: bool = typer.Option(True, help="judge alerts with the same CWE in one function together (--no-group to turn off)"),
        scanner_only: bool = typer.Option(False, help="Setup A: no model"),
        max_findings: Optional[int] = typer.Option(None),
        sarif: Optional[str] = typer.Option(None, help="use an existing Semgrep SARIF file"),
        bandit_json: Optional[str] = typer.Option(None, help="use an existing Bandit JSON file"),
        semgrep_config: List[str] = typer.Option(None, help="extra Semgrep config, e.g. p/python (needs internet)"),
        cwe: List[str] = typer.Option(None, help="judge only this CWE, e.g. --cwe CWE-89 (repeat for more)"),
        effort: Optional[str] = typer.Option(None, help="Claude effort: low | medium | high"),
        only_scored: Optional[str] = typer.Option(None, help="benchmark truth file: judge only alerts it can score")):
    """Scan a folder, judge each alert, apply the fail-open gate, and store the results."""
    cfg = Config(target=target, context_level=context, threshold=threshold, votes=votes, group=group, helper_dirs=helpers or [], skip_judge=scanner_only,
                 max_findings=max_findings, sarif_path=sarif, bandit_path=bandit_json, only_cwes=cwe or [],
                 only_scored=only_scored)
    if provider:
        cfg.provider = provider
    if model:
        cfg.model = model
    if effort:
        cfg.effort = effort
    if semgrep_config:
        cfg.semgrep_configs += semgrep_config
    run_id = pipeline.run(cfg)
    out = report.build(cfg.runs_dir, run_id)
    typer.echo(f"Run {run_id} done. Report: {out}")


@app.command("report")
def report_cmd(run_id: Optional[str] = None, runs_dir: str = Config().runs_dir):
    """Rebuild the HTML report for a run (default: latest)."""
    typer.echo(report.build(runs_dir, _resolve(run_id, runs_dir)))


@app.command("evaluate")
def evaluate_cmd(truth: str, run_id: Optional[str] = None, threshold: Optional[float] = None,
                 cwe: List[str] = typer.Option(None, help="score only this CWE (repeat for more)"),
                 runs_dir: str = Config().runs_dir):
    """Compare a run with benchmark truth (precision, recall, F1, F2, false positives removed, real findings lost)."""
    rid = _resolve(run_id, runs_dir)
    why = store.partial_reason(runs_dir, rid)
    if why:
        typer.echo(f"WARNING: run {rid} stopped early ({why}); its results are incomplete.", err=True)
    typer.echo(json.dumps(ev.evaluate(runs_dir, rid, truth, threshold, cwe or None), indent=2))


@app.command("sweep")
def sweep_cmd(truth: str, run_id: Optional[str] = None,
              cwe: List[str] = typer.Option(None, help="score only this CWE (repeat for more)"),
              runs_dir: str = Config().runs_dir):
    """Threshold sweep on stored verdicts (no new model calls)."""
    for row in ev.sweep(runs_dir, _resolve(run_id, runs_dir), truth, cwes=cwe or None):
        typer.echo(row)


@app.command("inspect")
def inspect_cmd(file: str = typer.Argument(..., help="part of a file name, e.g. BenchmarkTest00099"),
                level: int = typer.Option(2, help="context level to show: 1, 2 or 3"),
                show_prompt: bool = typer.Option(False, "--prompt", help="also print the full prompt sent to the model"),
                run_id: Optional[str] = None, runs_dir: str = Config().runs_dir):
    """Look inside the pipeline for one file: its alerts (step 2), the code slice (step 3) and the prompt (step 4).
    Uses the scanner output saved by an earlier run, so it is free and needs no model."""
    rid = _resolve(run_id, runs_dir)
    saved = store.load_config(runs_dir, rid)
    cfg = Config(**saved)
    run_dir = Path(runs_dir) / rid
    sarif = cfg.sarif_path or run_dir / "semgrep.sarif"
    bandit = cfg.bandit_path or run_dir / "bandit.json"
    findings = [f for f in ingest.parse_all(sarif, bandit, cfg.target, cfg.security_only, cfg.only_cwes) if file in f.file]
    if not findings:
        typer.echo(f"No alerts for '{file}' in run {rid}.")
        raise typer.Exit()
    for f in findings:
        typer.echo(f"\n=== ALERT {f.id}\n    CWE {f.cwe} (scanner said {f.scanner_cwe}) | lines {f.start_line}-{f.end_line}"
                   f" | {f.message[:100]}")
        if f.also_reported_by:
            typer.echo(f"    also reported by: {', '.join(f.also_reported_by)}")
        ctx = slicer.build(f, cfg.target, level=level)
        typer.echo(f"--- code slice, level {level} ({len(ctx.lines)} lines){': ' + ctx.note if ctx.note else ''}")
        typer.echo(ctx.render())
        if show_prompt:
            system, user = prompts.build(f, ctx, policy.for_cwe(f.cwe, cfg.policy_path, cfg.rubrics_dir))
            typer.echo(f"--- SYSTEM PROMPT\n{system}\n--- USER PROMPT\n{user}")


@app.command("ci")
def ci_cmd(target: str = typer.Argument(..., help="folder to scan, relative to the repository root (e.g. . or src)"),
           model: str = typer.Option("auto", help="auto (Claude Haiku if ANTHROPIC_API_KEY is set, else scanner only) | claude | sonnet | scanner | mock"),
           cwe: List[str] = typer.Option(None, help="only this CWE (repeat for more); default all six"),
           max_cost: float = typer.Option(1.0, help="stop the AI at this many US$; unchecked alerts are kept"),
           sarif_out: str = typer.Option("sast-triage.sarif", help="where to write the SARIF file"),
           summary: Optional[str] = typer.Option(None, help="append a Markdown summary here (GitHub: $GITHUB_STEP_SUMMARY)"),
           fail_on: str = typer.Option("confirmed", help="confirmed | review | never: which alerts fail the check"),
           annotate: bool = typer.Option(True, help="print GitHub annotations (--no-annotate to turn off)")):
    """For CI pipelines: scan with the frozen settings, write SARIF + summary, exit 1 if alerts match --fail-on."""
    from . import ci
    try:
        code = ci.run_ci(target, model=model, cwes=cwe, max_cost=max_cost, sarif_out=sarif_out,
                         summary_out=summary, fail_on=fail_on, annotate=annotate, echo=typer.echo)
    except (ValueError, RuntimeError) as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(2)
    raise typer.Exit(code)


@app.command("serve")
def serve_cmd(port: int = typer.Option(8765, help="port on this computer"),
              browser: bool = typer.Option(True, help="open the browser (--no-browser to only print the link)"),
              host: str = typer.Option("127.0.0.1", help="address to listen on; keep 127.0.0.1. Only the Docker image uses 0.0.0.0, "
                                                        "and compose.yaml then publishes the port on 127.0.0.1 only"),
              demo: bool = typer.Option(False, help="public read-only demo: no token, sample results only, nothing can be changed"),
              runs: str = typer.Option("", help="results folder to show (default: runs)")):
    """Start the web app on this computer only (127.0.0.1). Open the printed link; it holds this session's token."""
    import secrets
    import webbrowser

    import uvicorn

    from .server import create_app

    if demo:
        typer.echo(f"SAST Triage read-only demo on {host}:{port}. Nothing can be changed and no API key is used.")
        uvicorn.run(create_app(runs_dir=runs or None, port=port, demo=True), host=host, port=port, log_level="warning",
                    proxy_headers=True, forwarded_allow_ips="*")
        return
    token = secrets.token_urlsafe(32)
    url = f"http://127.0.0.1:{port}/#t={token}"
    typer.echo(f"SAST Triage is running on this computer only.\nOpen this link (it contains your session key, do not share it):\n  {url}\nPress Ctrl+C to stop.")
    if browser:
        webbrowser.open(url)
    uvicorn.run(create_app(runs_dir=runs or None, token=token, port=port), host=host, port=port, log_level="warning")


if __name__ == "__main__":
    app()
