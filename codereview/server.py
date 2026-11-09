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
- serve --demo (the public demo) is the one exception: anyone may read the results without a token. Visitors may
  scan small public GitHub repositories with the demo model only (no AI, no API key, one scan at a time);
  saving decisions and local folders are refused.
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
from .report import CWES, project_name
from .config import ROOT, Config


def _clean_error(e: Exception) -> str:
    """Short error text for the page: folder paths cut to the last part, keys and tokens masked.
    The full error still goes to the terminal log (traceback) for the owner."""
    text = str(e)[:300]
    text = re.sub(r"(sk-ant-[A-Za-z0-9_-]{3})[A-Za-z0-9_-]+", r"\1...", text)        # API keys
    text = re.sub(r"(?i)(token|key|password)=\S+", r"\1=...", text)
    text = re.sub(r"(?:[A-Za-z]:)?(?:[\\/][^\\/\s'\":]+){2,}[\\/]([^\\/\s'\":]+)", r".../\1", text)  # /a/b/c/file -> .../file
    return text


WEB = Path(__file__).parent / "web"
CONTEXT_LEVEL, THRESHOLD = 2, 0.6          # the settings frozen for the evaluation
FALLBACK_CALL_COST = 0.003                 # dollars per Claude call when there are no earlier runs to average
MODELS = {"claude": ("anthropic", "claude-haiku-5-5"), "sonnet": ("anthropic", "claude-sonnet-5-5"),
          "qwen": ("ollama", "qwen3:14b"), "mock": ("mock", "mock")}   # Haiku is the evaluated model; Sonnet is an extra, not evaluated
LABELS = {"real", "fp", "unsure"}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
       "base-uri 'none'; form-action 'none'")


# ------------------------------------------------------------------ helpers
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
    max_cost: Optional[float] = Field(default=None, ge=0, le=1000)   # spending limit in US$ (empty = no limit)


class StartRequest(BaseModel):
    max_cost: Optional[float] = Field(default=None, ge=0, le=1000)   # the spending limit can still be changed here


class FolderCheck(BaseModel):
    folder: str = Field(min_length=1, max_length=1000)


SKIP_DIRS = {".git", ".venv", "venv", "env", "node_modules", "__pycache__", ".tox", "site-packages"}


def count_py_files(folder: Path, cap: int = 20000) -> int:
    """How many Python files the scanners will read (stops counting at cap, so huge folders stay quick)."""
    n = 0
    for _root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        n += sum(f.endswith(".py") for f in files)
        if n >= cap:
            break
    return n


class ReviewRequest(BaseModel):
    run: str = Field(max_length=64)
    fid: str = Field(max_length=200)
    label: str
    note: str = Field(default="", max_length=2000)


class Jobs:
    """Scans run in a background thread so the page stays responsive. Only one AI check runs at a time."""

    def __init__(self, runs_dir: str, demo: bool = False):
        self.runs_dir = runs_dir
        self.demo = demo                       # public demo: GitHub links only, demo model only, small repos, one at a time
        self.jobs: dict = {}
        self.lock = threading.Lock()           # protects self.jobs
        self.judge_lock = threading.Lock()     # one AI run at a time: keeps cost and the database simple

    def public(self, job: dict) -> dict:
        out = {k: v for k, v in job.items() if k not in ("sarif", "bandit") and not k.startswith("_")}
        out["cancelling"] = bool(job.get("_cancel"))
        return out

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
        if self.demo:
            if not gh:
                raise HTTPException(400, "The online demo can only scan public GitHub links, like https://github.com/owner/repository")
            if self.active():
                raise HTTPException(429, "Another demo scan is running right now. Please try again in a minute.")
            req.model = "mock"                 # the demo never calls a paid or local AI model
            _rmtree(Path(self.runs_dir).resolve() / "app-repos")   # keep only the newest downloaded repository
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
               "run_id": None, "error": None, "max_cost": req.max_cost or None, "spent": 0.0, "partial": None}
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
                commit = clone_repo(owner, repo, ref, Path(job["folder"]), (DEMO_MAX_FILES, DEMO_MAX_ALL) if self.demo else None)
                if self.get(jid).get("_cancel"):
                    self.update(jid, state="cancelled")
                    return
                self.update(jid, state="counting", commit=commit)
            except TooBig as e:
                self.update(jid, state="error", error=str(e))
                return
            except Exception as e:
                traceback.print_exc()
                self.update(jid, state="error", error=f"Could not download the repository (is it public, and is the branch or commit right?): {_clean_error(e)}")
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
            provider, model = MODELS[job["model"]]
            per_sec = store.average_call_seconds(self.runs_dir, provider, model)   # from earlier runs, None if none
            seconds = round(n_groups * per_sec) if per_sec is not None else None
            warnings = [f"{name} produced no results file, so its alerts are missing. Check the terminal for its error."
                        for name, out in (("Semgrep", sarif), ("Bandit", bandit)) if not out]
            if self.get(jid).get("_cancel"):
                self.update(jid, state="cancelled")
                return
            self.update(jid, state="counted", alerts=alerts, groups=n_groups, estimate=estimate, warnings=warnings, est_seconds=seconds,
                        per_call=round(per_call, 5), sarif=str(sarif) if sarif else None,
                        bandit=str(bandit) if bandit else None)
        except Exception as e:     # show the person what went wrong instead of hanging
            traceback.print_exc()
            self.update(jid, state="error", error=f"The scanners failed: {type(e).__name__}: {_clean_error(e)}")

    def start(self, jid: str, max_cost: Optional[float] = None, set_limit: bool = False) -> dict:
        job = self.get(jid)
        if job["state"] != "counted":
            raise HTTPException(409, "This scan is not waiting to start.")
        if set_limit:                          # the page sends the limit again, in case it was changed after the cost check
            self.update(jid, max_cost=max_cost or None)
        self.update(jid, state="queued")
        threading.Thread(target=self._judge, args=(jid,), daemon=True).start()
        return self.public(self.get(jid))

    def _judge(self, jid: str) -> None:
        with self.judge_lock:
            job = self.get(jid)
            if job.get("_cancel"):                 # cancelled while waiting for another scan
                self.update(jid, state="cancelled")
                return
            provider, model = MODELS[job["model"]]
            cfg = Config(target=job["folder"], provider=provider, model=model, context_level=CONTEXT_LEVEL,
                         threshold=THRESHOLD, only_cwes=job["cwes"], sarif_path=job["sarif"],
                         bandit_path=job["bandit"], runs_dir=self.runs_dir)
            self.update(jid, state="judging", total=job["groups"])

            def progress(done, total, finding):
                self.update(jid, done=done, total=total, current=f"{Path(finding.file).name}:{finding.start_line}")

            def should_stop(spent: float) -> Optional[str]:
                now = self.get(jid)
                self.update(jid, spent=round(spent, 4))
                if now.get("_cancel"):
                    return "you cancelled the scan"
                limit = now.get("max_cost")
                if limit is not None and spent + (now.get("per_call") or 0) > limit:   # stop before going over
                    return f"spending limit of ${limit:g} reached"
                return None

            try:
                run_id = pipeline.run(cfg, progress=progress, should_stop=should_stop)
                report.build(self.runs_dir, run_id)
                self.update(jid, state="done", run_id=run_id, done=job["groups"],
                            partial=store.partial_reason(self.runs_dir, run_id))
            except Exception as e:
                traceback.print_exc()
                self.update(jid, state="error", error=f"The AI check stopped: {type(e).__name__}: {_clean_error(e)}")

    def cancel(self, jid: str) -> dict:
        job = self.get(jid)
        if job["state"] in ("done", "error", "cancelled"):
            raise HTTPException(409, "This scan has already finished.")
        self.update(jid, _cancel=True)
        if job["state"] == "counted":          # nothing running yet: stop at once
            self.update(jid, state="cancelled")
        return self.public(self.get(jid))

    def active(self) -> list:
        with self.lock:
            return [self.public(j) for j in self.jobs.values() if j["state"] not in ("done", "error", "cancelled")]


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


class TooBig(Exception):
    """The repository is over the online demo's limits (checked before any file content is downloaded)."""


def clone_repo(owner: str, repo: str, ref: str, dest: Path, limits: Optional[tuple] = None) -> str:
    """Download only the needed version (no history, no submodules). The code is only read by the scanners,
    never run. Returns the short commit id, so results can be repeated.
    limits=(max Python files, max files): the demo first downloads only the list of file names, and refuses
    big repositories before downloading any file content."""
    _rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    first = ["--filter=blob:none", "--no-checkout"] if limits else []
    _git(["clone", "--depth", "1", "--no-recurse-submodules", "--quiet", *first, f"https://github.com/{owner}/{repo}.git", str(dest)])
    target = "HEAD"
    if ref:
        try:
            _git(["fetch", "--depth", "1", "--quiet", *(["--filter=blob:none"] if limits else []), "origin", ref], cwd=dest)
        except RuntimeError as e:
            if re.fullmatch(r"[0-9a-fA-F]{4,39}", ref):    # GitHub only serves a commit by its full 40-character id
                raise RuntimeError("use the full 40-character commit id, not the short one") from e
            raise
        target = "FETCH_HEAD"
    if limits:
        names = _git(["ls-tree", "-r", "--name-only", target], cwd=dest).splitlines()   # names only: no file content yet
        py = sum(n.endswith(".py") for n in names)
        if py > limits[0] or len(names) > limits[1]:
            _rmtree(dest)
            raise TooBig(f"This repository has {py} Python files and {len(names)} files in all. The online demo takes up to "
                         f"{limits[0]} Python files and {limits[1]} files. Install the app from GitHub to scan big projects.")
        _git(["checkout", "--quiet", "--detach", target], cwd=dest)
    elif ref:
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
def latest_runs(runs_dir: str, rows: Optional[List[dict]] = None) -> List[dict]:
    """The newest run of each scanned folder: what the dashboard and the issue list show by default."""
    seen, out = set(), []
    for r in (rows if rows is not None else store.list_runs(runs_dir)):
        if r["target"] in seen:
            continue
        seen.add(r["target"])
        out.append(r)
    return out


def _line_text(target: str, file: str, line: int, cache: dict) -> str:
    """The flagged line's code from disk, for alerts the AI never saw (scanner only, or not checked)."""
    if file not in cache:
        try:
            cache[file] = (Path(target) / file).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            cache[file] = []
    lines = cache[file]
    return lines[line - 1] if 0 < line <= len(lines) else ""


def fingerprints(rows: List[dict], target: str = "") -> dict:
    """finding id -> a key that survives code moving up or down: scanner rule + file + the flagged line's code,
    plus a counter when the same code repeats in a file. Line numbers are not part of the key."""
    cache: dict = {}
    keyed = []
    for r in rows:
        f, ctx = r["finding"], r["context"] or {}
        text = next((t for n, t in ctx.get("lines", []) if n == f["start_line"]), None)
        if text is None and target:
            text = _line_text(target, f["file"], f["start_line"], cache)
        base = "|".join([f["tool"], f["rule_id"].split(".")[-1], f["file"].replace("\\", "/"), " ".join((text or "").split())])
        keyed.append((base, f["start_line"], f["id"]))
    out, seen = {}, {}
    for base, _, fid in sorted(keyed):
        k = seen.get(base, 0)
        seen[base] = k + 1
        out[fid] = f"{base}|{k}"
    return out


def previous_run(runs_dir: str, run_id: str, runs: Optional[List[dict]] = None) -> Optional[str]:
    """The scan of the same folder just before this one (complete scans only)."""
    runs = runs if runs is not None else store.list_runs(runs_dir)   # newest first
    ids = [r["id"] for r in runs]
    if run_id not in ids:
        return None
    target = runs[ids.index(run_id)]["target"]
    for r in runs[ids.index(run_id) + 1:]:
        if r["target"] == target and not r["partial"]:
            return r["id"]
    return None


def issues_for(runs_dir: str, run_ids: List[str]) -> List[dict]:
    out = []
    runs = store.list_runs(runs_dir)          # read once, not once per scan
    for rid in run_ids:
        cfg = store.load_config(runs_dir, rid)
        target = cfg.get("target", "")
        project = project_name(target)
        reviews = store.load_reviews(runs_dir, rid)
        log = store.load_review_log(runs_dir, rid)
        rows = store.load_run(runs_dir, rid)
        prev = previous_run(runs_dir, rid, runs)
        keys = fingerprints(rows, target) if prev else {}
        old = set(fingerprints(store.load_run(runs_dir, prev), target).values()) if prev else set()
        for row in rows:
            i = to_issue(rid, project, row, reviews.get(row["finding"]["id"]))
            i["new"] = (keys[row["finding"]["id"]] not in old) if prev else None   # None: first scan of this folder
            i["history"] = log.get(row["finding"]["id"], [])
            out.append(i)
    return out


def scan_history(runs_dir: str, cache: dict) -> List[dict]:
    """Every scan, oldest first, with how many alerts were new and how many had gone since the scan before it
    (same folder, matched by fingerprint). Finished scans never change, so their counts are cached."""
    runs = store.list_runs(runs_dir)
    out = []
    for r in reversed(runs):
        prev = previous_run(runs_dir, r["id"], runs)
        key = (r["id"], r["alerts"], prev)
        if key not in cache:
            new = gone = None
            if prev:
                a = set(fingerprints(store.load_run(runs_dir, prev), r["target"]).values())
                b = set(fingerprints(store.load_run(runs_dir, r["id"]), r["target"]).values())
                new, gone = len(b - a), len(a - b)
            cache[key] = (new, gone)
        new, gone = cache[key]
        out.append({"id": r["id"], "created": r["created"], "project": project_name(r["target"]), "target": r["target"],
                    "model": r["model"], "provider": r["provider"], "alerts": r["alerts"], "hidden": r["hidden"],
                    "confirmed": r["confirmed"], "partial": r["partial"], "new": new, "gone": gone})
    return out


def compare_runs(runs_dir: str, a: str, b: str) -> dict:
    """Which alerts changed AI result between two scans. Alerts are matched by fingerprint, not by line number."""
    ca, cb = store.load_config(runs_dir, a), store.load_config(runs_dir, b)
    ra, rb = store.load_run(runs_dir, a), store.load_run(runs_dir, b)
    ka, kb = fingerprints(ra, ca.get("target", "")), fingerprints(rb, cb.get("target", ""))
    ia = {ka[r["finding"]["id"]]: to_issue(a, "", r, None) for r in ra}
    ib = {kb[r["finding"]["id"]]: to_issue(b, "", r, None) for r in rb}
    rows = []
    for key in sorted(set(ia) | set(ib), key=lambda k: ((ib.get(k) or ia.get(k))["file"], (ib.get(k) or ia.get(k))["line"])):
        x, y = ia.get(key), ib.get(key)
        z = y or x
        side = lambda i: {"group": i["group"], "verdict": i["verdict"], "conf": i["conf"], "reason": i["reason"],
                          "line": i["line"], "fid": i["fid"]} if i else None
        rows.append({"file": z["file"], "cwe": z["cwe"], "sev": z["sev"], "rule": z["rule"], "tool": z["tool"],
                     "a": side(x), "b": side(y),
                     "change": "only_a" if not y else "only_b" if not x else "same" if x["group"] == y["group"] else "changed"})
    count = {k: sum(r["change"] == k for r in rows) for k in ("same", "changed", "only_a", "only_b")}
    warnings = []
    if ca.get("target") != cb.get("target"):
        warnings.append("These scans are of different folders, so most alerts will not match.")
    elif count["only_a"] or count["only_b"]:
        warnings.append("Some alerts exist in only one scan. If the code changed between the scans, "
                        "differences can come from the code and not from the model.")
    for rid in (a, b):
        why = store.partial_reason(runs_dir, rid)
        if why:
            warnings.append(f"Scan {rid} stopped early ({why}), so some of its alerts were not checked.")
    summary = lambda rid, c, rows_: {"id": rid, "project": project_name(c.get("target", "")), "model": c.get("model"),
                                     "provider": c.get("provider"), "alerts": len(rows_),
                                     "hidden": sum(r["decision"]["action"] == "suppress" for r in rows_)}
    return {"a": summary(a, ca, ra), "b": summary(b, cb, rb), "rows": rows, "count": count, "warnings": warnings}


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
DEMO_BLOCKED = "Saving decisions is turned off in the online demo. Install the app from GitHub to use every feature."
DEMO_POSTS = re.compile(r"^/api/(scans|scans/[0-9a-f]{12}/(start|cancel)|check-folder)$")   # what demo visitors may do
DEMO_MAX_FILES = 300          # Python files per demo scan
DEMO_MAX_ALL = 3000           # files of any kind per demo scan


def create_app(runs_dir: Optional[str] = None, token: Optional[str] = None, port: int = 8765,
               extra_hosts: tuple = (), demo: bool = False) -> FastAPI:
    """demo=True: the public read-only demo. Anyone may read the sample results (no token, any host), but every
    call that changes something or starts work (scans, decisions, folder checks) is refused, and no API key is used."""
    runs_dir = runs_dir or Config().runs_dir
    token = token or secrets.token_urlsafe(32)
    jobs = Jobs(runs_dir, demo=demo)
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", *extra_hosts}   # extra_hosts: only for tests
    app = FastAPI(title="SAST Triage", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.token, app.state.jobs = token, jobs
    history_cache: dict = {}

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if demo:
            if request.url.path.startswith("/api/") and request.method not in ("GET", "HEAD") and not DEMO_POSTS.match(request.url.path):
                return JSONResponse({"detail": DEMO_BLOCKED}, status_code=403)
            resp = await call_next(request)
            resp.headers["Content-Security-Policy"] = CSP
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["Referrer-Policy"] = "no-referrer"
            resp.headers["X-Frame-Options"] = "SAMEORIGIN"
            return resp
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
                "anthropic_key": False if demo else bool(os.getenv("ANTHROPIC_API_KEY")), "demo": demo,
                "context_level": CONTEXT_LEVEL, "threshold": THRESHOLD,
                "models": {k: {"provider": p, "model": m} for k, (p, m) in MODELS.items()},
                "cwes": {c: {"name": n, "sev": s, "owasp": rules.get(c, {}).get("owasp", ""),
                         "rule": rules.get(c, {}).get("id", ""), "title": rules.get(c, {}).get("title", "")}
                     for c, (n, s) in CWES.items()},
                "runs_dir": "demo" if demo else str(runs_dir)}

    @app.get("/api/runs")
    def runs():
        rows = store.list_runs(runs_dir)
        latest = {r["id"] for r in latest_runs(runs_dir, rows)}
        return [dict(r, project=project_name(r["target"]), latest=r["id"] in latest,
                     model="mock" if r["provider"] == "mock" and r["model"] != "scanner only" else r["model"])
                for r in rows]

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
        if req.label == "clear":
            store.clear_review(runs_dir, req.run, req.fid)
            return {"ok": True}
        if req.label not in LABELS:
            raise HTTPException(400, "Unknown label")
        store.save_review(runs_dir, req.run, req.fid, req.label, req.note)
        return {"ok": True}

    @app.get("/api/history")
    def history():
        return scan_history(runs_dir, history_cache)

    @app.get("/api/decisions.csv")
    def decisions_csv():
        """Every decision a person saved, on any scan, with the note and when it was last changed."""
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["project", "file", "line", "cwe", "severity", "ai_result", "ai_verdict", "ai_confidence",
                    "your_decision", "your_note", "decided_at", "scan"])
        for i in issues_for(runs_dir, store.runs_with_reviews(runs_dir)):
            r = i["review"]
            if not r:
                continue
            w.writerow([safe_cell(x) for x in (i["project"], i["file"], i["line"], i["cwe"], i["sev"], i["group"],
                                                i["verdict"], i["conf"], r["label"], r["note"], r["updated"], i["run"])])
        return Response(buf.getvalue(), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": 'attachment; filename="decisions.csv"'})
    @app.get("/api/compare")
    def compare(a: str, b: str):
        _check_run(a)
        _check_run(b)
        return compare_runs(runs_dir, a, b)

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
    def start(jid: str, req: Optional[StartRequest] = None):
        return jobs.start(jid, req.max_cost if req else None, set_limit=req is not None)

    @app.post("/api/check-folder")
    def check_folder(req: FolderCheck):
        """Before a scan: is this a usable GitHub link, or a folder that exists on this computer (or in Docker)?"""
        if parse_github(req.folder):       # raises a clear 400 for a malformed GitHub link; no download here
            return {"kind": "github", "ok": True}
        if demo:
            return {"kind": "folder", "ok": False, "error": "The online demo can only scan public GitHub links."}
        folder = resolve_folder(req.folder)
        if not folder:
            return {"kind": "folder", "ok": False}
        return {"kind": "folder", "ok": True, "py_files": count_py_files(folder), "project": project_name(str(folder))}

    @app.post("/api/scans/{jid}/cancel")
    def cancel(jid: str):
        return jobs.cancel(jid)

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
