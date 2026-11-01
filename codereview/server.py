"""Local web app for the tool.   Start it with:   python -m codereview serve

A small FastAPI server with a JSON API, plus the web page in codereview/web/. It calls the same pipeline
as the command line with the frozen settings (context level 2, threshold 0.6), so it changes nothing in
how alerts are judged. It adds: starting scans without typing commands, a dashboard, reading results,
recording a person's decision on each alert, and CSV / SARIF / HTML exports.

Security (this app can read folders and spend API money, so only its owner may use it):
- It listens on 127.0.0.1 only, so other computers cannot reach it.
- Every API call must carry a random session token (made fresh at each start, shown only in the start
  link). Other websites open in the same browser cannot read it, so they cannot call the API.
- The Host header must be 127.0.0.1 or localhost (blocks DNS rebinding attacks).
- Code, file names and model text are untrusted: the page only ever shows them as plain text.
- CSV cells that start with = + - @ get a leading ' so spreadsheet programs do not run them as formulas.
- The API key stays in .env. The API only says whether one exists.
"""
import csv
import io
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import threading
import traceback
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import llm, pipeline, policy, report, store
from .config import ROOT, Config

WEB = Path(__file__).parent / "web"
CONTEXT_LEVEL, THRESHOLD = 2, 0.6          # the settings frozen for the evaluation
FALLBACK_CALL_COST = 0.003                 # dollars per Claude call when there are no earlier runs to average
MODELS = {"claude": ("anthropic", "claude-haiku-5-5"), "sonnet": ("anthropic", "claude-sonnet-5-5"),
          "qwen": ("ollama", "qwen3:14b"), "mock": ("mock", "mock")}   # Haiku is the evaluated model; Sonnet is an extra, not evaluated
CWES = {"CWE-89": ("SQL injection", "high"), "CWE-78": ("OS command injection", "high"),
        "CWE-95": ("Code injection", "critical"), "CWE-502": ("Unsafe deserialization", "critical"),
        "CWE-611": ("XML external entities", "high"), "CWE-614": ("Cookie without Secure flag", "medium")}
LABELS = {"real", "fp", "unsure"}
GENERIC = {"src", "web", "app", "lib", "code", "python"}   # folder names that say nothing about the project
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
       "base-uri 'none'; form-action 'none'")


# ------------------------------------------------------------------ helpers
def project_name(target: str) -> str:
    p = Path(str(target).replace("\\", "/"))
    if p.name.lower() in GENERIC and p.parent.name:
        return f"{p.parent.name}/{p.name}"
    return p.name or str(target)


def group_of(row: dict) -> str:
    """Same three groups as the HTML report. Alerts the model did not judge are kept for review."""
    if row["decision"]["action"] == "suppress":
        return "Hidden"
    if row["verdict"] and row["verdict"]["verdict"] == "confirmed":
        return "Confirmed"
    return "Needs review"


def to_issue(run_id: str, project: str, row: dict, review: Optional[dict]) -> dict:
    f, v, ctx = row["finding"], row["verdict"] or {}, row["context"] or {}
    return {
        "id": f"{run_id}/{f['id']}", "run": run_id, "fid": f["id"], "project": project,
        "file": f["file"].replace("\\", "/"), "line": f["start_line"], "end": f["end_line"],
        "cwe": f.get("cwe") or "unknown", "sev": CWES.get(f.get("cwe"), ("", "medium"))[1],
        "tool": f["tool"], "rule": f["rule_id"].split(".")[-1], "rule_full": f["rule_id"], "msg": f["message"],
        "also": f.get("also_reported_by", []), "group": group_of(row),
        "verdict": v.get("verdict"), "conf": v.get("confidence_score"), "reason": v.get("reasoning", ""),
        "fix": v.get("suggested_fix", ""), "sanitized": v.get("sanitization_present"),
        "feasible": v.get("attack_feasible"), "policy": v.get("policy_rule_id"),
        "evidence": [[f"{e['file']}:{e['lines']}", e.get("why", "")] for e in v.get("evidence", [])],
        "code": ctx.get("lines", []), "helpers": ctx.get("helpers", []), "note": ctx.get("note", ""),
        "decision": row["decision"]["reason"], "verified": row["verified"],
        "review": review,
    }


def safe_cell(value) -> str:
    """Stop CSV formula injection: spreadsheet programs run cells that start with = + - @ as formulas."""
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


# ------------------------------------------------------------------ scan jobs
class ScanRequest(BaseModel):
    folder: str = Field(min_length=1, max_length=1000)     # a folder on this computer, or a public GitHub link
    ref: str = Field(default="", max_length=100)          # GitHub only: branch, tag or commit (empty = default branch)
    cwes: List[str] = Field(min_length=1)
    model: str = "claude"


class ReviewRequest(BaseModel):
    run: str = Field(max_length=64)
    fid: str = Field(max_length=200)
    label: str
    note: str = Field(default="", max_length=2000)


class Jobs:
    """Scans run in a background thread so the page stays responsive. Only one AI check runs at a time."""

    def __init__(self, runs_dir: str):
        self.runs_dir = runs_dir
        self.jobs: dict = {}
        self.lock = threading.Lock()           # protects self.jobs
        self.judge_lock = threading.Lock()     # one AI run at a time: keeps cost and the database simple

    def public(self, job: dict) -> dict:
        return {k: v for k, v in job.items() if k not in ("sarif", "bandit") and not k.startswith("_")}

    def update(self, jid: str, **kw) -> None:
        with self.lock:
            self.jobs[jid].update(kw)

    def get(self, jid: str) -> dict:
        with self.lock:
            if jid not in self.jobs:
                raise HTTPException(404, "No such scan")
            return dict(self.jobs[jid])

    def create(self, req: ScanRequest) -> dict:
        gh = parse_github(req.folder, req.ref)
        if gh:
            if not shutil.which("git"):
                raise HTTPException(400, "Git is not installed, so GitHub links cannot be downloaded.")
            owner, repo, ref = gh
            safe_ref = re.sub(r"[^A-Za-z0-9._-]", "_", ref) if ref else "latest"
            folder = Path(self.runs_dir).resolve() / "app-repos" / owner / safe_ref / repo   # folder name = repo name
        else:
            folder = resolve_folder(req.folder)
            if not folder:
                raise HTTPException(400, "That folder does not exist on this computer. For GitHub, paste a link like https://github.com/owner/repository")
        cwes = [c for c in req.cwes if c in CWES]
        if not cwes:
            raise HTTPException(400, "Pick at least one weakness type.")
        if req.model not in MODELS:
            raise HTTPException(400, "Unknown model.")
        missing = [t for t in ("semgrep", "bandit") if not shutil.which(t)]
        if missing:
            raise HTTPException(400, f"Not found: {', '.join(missing)}. Activate the project's virtual environment and start the app again.")
        if MODELS[req.model][0] == "anthropic" and not os.getenv("ANTHROPIC_API_KEY"):
            raise HTTPException(400, "No ANTHROPIC_API_KEY in .env. Add it and start the app again.")
        jid = uuid.uuid4().hex[:12]
        job = {"id": jid, "state": "cloning" if gh else "counting", "folder": str(folder), "project": project_name(str(folder)),
               "github": f"github.com/{gh[0]}/{gh[1]}" + (f" @ {gh[2]}" if gh[2] else "") if gh else None, "commit": None, "_gh": gh,
               "cwes": cwes, "model": req.model, "created": datetime.now().isoformat(timespec="seconds"),
               "alerts": None, "groups": None, "estimate": None, "done": 0, "total": 0, "current": "",
               "run_id": None, "error": None}
        with self.lock:
            self.jobs[jid] = job
            snapshot = self.public(job)            # copy now: the thread below starts changing the job at once
        threading.Thread(target=self._count, args=(jid,), daemon=True).start()
        return snapshot

    def _count(self, jid: str) -> None:
        job = self.get(jid)
        if job["state"] == "cloning":
            try:
                owner, repo, ref = job["_gh"]
                commit = clone_repo(owner, repo, ref, Path(job["folder"]))
                self.update(jid, state="counting", commit=commit)
            except Exception as e:
                traceback.print_exc()
                self.update(jid, state="error", error=f"Could not download the repository (is it public, and is the branch or commit right?): {str(e)[:300]}")
                return
        try:
            scan_dir = Path(self.runs_dir) / "app-scans" / f"{datetime.now():%Y%m%d-%H%M%S}-{jid}"
            scan_dir.mkdir(parents=True, exist_ok=True)
            sarif, bandit, groups = pipeline.collect(
                Config(target=job["folder"], only_cwes=job["cwes"], runs_dir=self.runs_dir), scan_dir)
            n_groups, alerts = len(groups), sum(len(g) for g in groups)
            if MODELS[job["model"]][0] == "anthropic":
                model = MODELS[job["model"]][1]
                per_call = store.average_call_cost(self.runs_dir, "anthropic", model)
                if not per_call:       # no earlier runs with this model: scale Haiku's average by the price difference
                    base = store.average_call_cost(self.runs_dir, "anthropic", "claude-haiku-5-5") or FALLBACK_CALL_COST
                    per_call = base * llm.PRICES.get(model, (0.10, 0.50))[1] / llm.PRICES["claude-haiku-5-5"][1]
                estimate = round(n_groups * per_call, 4)
            else:
                per_call, estimate = 0.0, 0.0
            warnings = [f"{name} produced no results file, so its alerts are missing. Check the terminal for its error."
                        for name, out in (("Semgrep", sarif), ("Bandit", bandit)) if not out]
            self.update(jid, state="counted", alerts=alerts, groups=n_groups, estimate=estimate, warnings=warnings,
                        per_call=round(per_call, 5), sarif=str(sarif) if sarif else None,
                        bandit=str(bandit) if bandit else None)
        except Exception as e:     # show the person what went wrong instead of hanging
            traceback.print_exc()
            self.update(jid, state="error", error=f"The scanners failed: {type(e).__name__}: {str(e)[:300]}")

    def start(self, jid: str) -> dict:
        job = self.get(jid)
        if job["state"] != "counted":
            raise HTTPException(409, "This scan is not waiting to start.")
        self.update(jid, state="queued")
        threading.Thread(target=self._judge, args=(jid,), daemon=True).start()
        return self.public(self.get(jid))

    def _judge(self, jid: str) -> None:
        with self.judge_lock:
            job = self.get(jid)
            provider, model = MODELS[job["model"]]
            cfg = Config(target=job["folder"], provider=provider, model=model, context_level=CONTEXT_LEVEL,
                         threshold=THRESHOLD, only_cwes=job["cwes"], sarif_path=job["sarif"],
                         bandit_path=job["bandit"], runs_dir=self.runs_dir)
            self.update(jid, state="judging", total=job["groups"])

            def progress(done, total, finding):
                self.update(jid, done=done, total=total, current=f"{Path(finding.file).name}:{finding.start_line}")

            try:
                run_id = pipeline.run(cfg, progress=progress)
                report.build(self.runs_dir, run_id)
                self.update(jid, state="done", run_id=run_id, done=job["groups"])
            except Exception as e:
                traceback.print_exc()
                self.update(jid, state="error", error=f"The AI check stopped: {type(e).__name__}: {str(e)[:300]}")

    def active(self) -> list:
        with self.lock:
            return [self.public(j) for j in self.jobs.values() if j["state"] not in ("done", "error")]


GITHUB = re.compile(r"^https://github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9._-]{1,100}?)(?:\.git)?(?:/tree/([A-Za-z0-9._/-]{1,100}))?/?$")
REF = re.compile(r"^[A-Za-z0-9._/-]{1,100}$")


def parse_github(text: str, ref: str = ""):
    """Return (owner, repo, ref) for a public GitHub link, None if the text is not a GitHub link.
    Only plain https://github.com/owner/repo links are accepted: no other hosts, no ssh, file:// or ext:: URLs."""
    text = text.strip()
    if not re.match(r"^(https?://)?(www\.)?github\.com/", text, re.I):
        return None
    if not text.lower().startswith("https://"):
        text = "https://" + re.sub(r"^(https?://)?(www\.)?", "", text, flags=re.I)
    m = GITHUB.match(text)
    if not m or m.group(2) in (".", ".."):
        raise HTTPException(400, "Use a link like https://github.com/owner/repository")
    ref = (ref or m.group(3) or "").strip()
    if ref and (not REF.match(ref) or ref.startswith(("-", "/")) or ".." in ref):
        raise HTTPException(400, "The branch, tag or commit name has characters that are not allowed.")
    return m.group(1), m.group(2), ref


def _git(args: list, cwd: Optional[Path] = None, timeout: int = 900) -> str:
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1")   # never ask for a password
    r = subprocess.run(["git", "-c", "core.longpaths=true", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
                        *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).strip()[-300:] or "git failed")
    return r.stdout.strip()


def _rmtree(path: Path) -> None:
    def make_writable(func, p, _):        # git marks some files read-only, which Windows refuses to delete
        os.chmod(p, stat.S_IWRITE)
        func(p)
    if path.exists():
        shutil.rmtree(path, onerror=make_writable)


def clone_repo(owner: str, repo: str, ref: str, dest: Path) -> str:
    """Download only the needed version (no history, no submodules). The code is only read by the scanners,
    never run. Returns the short commit id, so results can be repeated."""
    _rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    _git(["clone", "--depth", "1", "--no-recurse-submodules", "--quiet", f"https://github.com/{owner}/{repo}.git", str(dest)])
    if ref:
        try:
            _git(["fetch", "--depth", "1", "--quiet", "origin", ref], cwd=dest)
        except RuntimeError as e:
            if re.fullmatch(r"[0-9a-fA-F]{4,39}", ref):    # GitHub only serves a commit by its full 40-character id
                raise RuntimeError("use the full 40-character commit id, not the short one") from e
            raise
        _git(["checkout", "--quiet", "--detach", "FETCH_HEAD"], cwd=dest)
    return _git(["rev-parse", "--short", "HEAD"], cwd=dest)


def resolve_folder(text: str) -> Optional[Path]:
    p = Path(text.strip().strip('"').strip("'")).expanduser()
    if not p.is_absolute():
        p = ROOT / p
    try:
        p = p.resolve()
    except OSError:
        return None
    return p if p.is_dir() else None


# ------------------------------------------------------------------ data for the page
def latest_runs(runs_dir: str) -> List[dict]:
    """The newest run of each scanned folder: what the dashboard and the issue list show by default."""
    seen, out = set(), []
    for r in store.list_runs(runs_dir):
        if r["target"] in seen:
            continue
        seen.add(r["target"])
        out.append(r)
    return out


def issues_for(runs_dir: str, run_ids: List[str]) -> List[dict]:
    out = []
    for rid in run_ids:
        cfg = store.load_config(runs_dir, rid)
        project = project_name(cfg.get("target", ""))
        reviews = store.load_reviews(runs_dir, rid)
        out += [to_issue(rid, project, row, reviews.get(row["finding"]["id"])) for row in store.load_run(runs_dir, rid)]
    return out


def sarif_for(issues: List[dict]) -> dict:
    rules, results = {}, []
    for i in issues:
        rid = i["rule_full"]
        rules.setdefault(rid, {"id": rid, "name": i["rule"], "shortDescription": {"text": i["msg"][:200] or rid},
                               "properties": {"tags": ["security", i["cwe"]]}})
        res = {"ruleId": rid, "level": "warning" if i["sev"] == "medium" else "error",
               "message": {"text": i["msg"] or rid},
               "locations": [{"physicalLocation": {"artifactLocation": {"uri": i["file"]},
                                                   "region": {"startLine": i["line"], "endLine": i["end"]}}}],
               "properties": {"ai_group": i["group"], "ai_verdict": i["verdict"], "ai_confidence": i["conf"],
                              "ai_reason": i["reason"], "suggested_fix": i["fix"]}}
        if i["group"] == "Hidden":       # shown as dismissed in GitHub code scanning, with the reason kept
            res["suppressions"] = [{"kind": "external", "status": "accepted",
                                    "justification": f"AI triage: {i['decision']}"}]
        results.append(res)
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "SAST Triage", "informationUri": "https://github.com/zainab-nooh/llm-sast-triage",
                                          "rules": list(rules.values())}}, "results": results}]}


# ------------------------------------------------------------------ the app
def create_app(runs_dir: Optional[str] = None, token: Optional[str] = None, port: int = 8765,
               extra_hosts: tuple = ()) -> FastAPI:
    runs_dir = runs_dir or Config().runs_dir
    token = token or secrets.token_urlsafe(32)
    jobs = Jobs(runs_dir)
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", *extra_hosts}   # extra_hosts: only for tests
    app = FastAPI(title="SAST Triage", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.token, app.state.jobs = token, jobs

    @app.middleware("http")
    async def guard(request: Request, call_next):
        host = request.headers.get("host", "")
        if host not in allowed_hosts:
            return JSONResponse({"detail": "Wrong host"}, status_code=403)
        origin = request.headers.get("origin")
        if origin and origin.split("://", 1)[-1] not in allowed_hosts:
            return JSONResponse({"detail": "Wrong origin"}, status_code=403)
        if request.url.path.startswith("/api/"):
            sent = request.headers.get("x-token", "")
            if not secrets.compare_digest(sent.encode(), token.encode()):
                return JSONResponse({"detail": "Missing or wrong session token. Open the link printed when the app started."}, status_code=401)
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/api/status")
    def status():
        rules = policy.load_policy(Config().policy_path)
        return {"tools": {t: bool(shutil.which(t)) for t in ("semgrep", "bandit")},
                "anthropic_key": bool(os.getenv("ANTHROPIC_API_KEY")),
                "context_level": CONTEXT_LEVEL, "threshold": THRESHOLD,
                "models": {k: {"provider": p, "model": m} for k, (p, m) in MODELS.items()},
                "cwes": {c: {"name": n, "sev": s, "owasp": rules.get(c, {}).get("owasp", ""),
                         "rule": rules.get(c, {}).get("id", ""), "title": rules.get(c, {}).get("title", "")}
                     for c, (n, s) in CWES.items()},
                "runs_dir": str(runs_dir)}

    @app.get("/api/runs")
    def runs():
        latest = {r["id"] for r in latest_runs(runs_dir)}
        return [dict(r, project=project_name(r["target"]), latest=r["id"] in latest,
                     model="mock" if r["provider"] == "mock" and r["model"] != "scanner only" else r["model"])
                for r in store.list_runs(runs_dir)]

    @app.get("/api/issues")
    def issues(run: Optional[str] = None):
        ids = [run] if run else [r["id"] for r in latest_runs(runs_dir)]
        return issues_for(runs_dir, ids)

    def _check_run(run_id: str) -> None:
        if not store.load_config(runs_dir, run_id):
            raise HTTPException(404, "No such run")

    @app.post("/api/reviews")
    def review(req: ReviewRequest):
        _check_run(req.run)
        if req.label not in LABELS:
            raise HTTPException(400, "Unknown label")
        store.save_review(runs_dir, req.run, req.fid, req.label, req.note)
        return {"ok": True}

    @app.get("/api/scans")
    def scans():
        return jobs.active()

    @app.post("/api/scans")
    def new_scan(req: ScanRequest):
        return jobs.create(req)

    @app.get("/api/scans/{jid}")
    def scan(jid: str):
        return jobs.public(jobs.get(jid))

    @app.post("/api/scans/{jid}/start")
    def start(jid: str):
        return jobs.start(jid)

    @app.get("/api/runs/{run_id}/export.csv")
    def export_csv(run_id: str):
        _check_run(run_id)
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["project", "file", "line", "cwe", "severity", "scanner", "rule", "ai_result", "ai_verdict",
                    "ai_confidence", "ai_reason", "suggested_fix", "your_decision", "your_note"])
        for i in issues_for(runs_dir, [run_id]):
            r = i["review"] or {}
            w.writerow([safe_cell(x) for x in (i["project"], i["file"], i["line"], i["cwe"], i["sev"], i["tool"],
                                                i["rule_full"], i["group"], i["verdict"], i["conf"], i["reason"],
                                                i["fix"], r.get("label", ""), r.get("note", ""))])
        return Response(buf.getvalue(), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="triage-{run_id}.csv"'})

    @app.get("/api/runs/{run_id}/export.sarif")
    def export_sarif(run_id: str):
        _check_run(run_id)
        return Response(json.dumps(sarif_for(issues_for(runs_dir, [run_id])), indent=1), media_type="application/sarif+json",
                        headers={"Content-Disposition": f'attachment; filename="triage-{run_id}.sarif"'})

    @app.get("/api/runs/{run_id}/report.html")
    def export_report(run_id: str):
        _check_run(run_id)
        path = report.build(runs_dir, run_id)
        return FileResponse(path, media_type="text/html", filename=f"report-{run_id}.html")

    app.mount("/", StaticFiles(directory=WEB, html=True), name="web")
    return app
