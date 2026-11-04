"""Step 8: save everything to SQLite (results) and JSONL (raw model replies). Reports and evaluation read from here."""
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .config import Config

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, created TEXT, config TEXT);
CREATE TABLE IF NOT EXISTS results (
  run_id TEXT, finding_id TEXT, finding TEXT, context TEXT, verdict TEXT, decision TEXT, verified INTEGER,
  tokens_in INTEGER, tokens_out INTEGER, cost REAL, seconds REAL
);
CREATE TABLE IF NOT EXISTS reviews (
  run_id TEXT, finding_id TEXT, label TEXT, note TEXT, updated TEXT, PRIMARY KEY (run_id, finding_id)
);
CREATE TABLE IF NOT EXISTS run_status (run_id TEXT PRIMARY KEY, partial TEXT);
CREATE INDEX IF NOT EXISTS results_by_run ON results (run_id);
"""


_READY = set()   # databases whose tables were already created by this process


def connect(runs_dir: str) -> sqlite3.Connection:
    db = Path(runs_dir) / "results.db"
    key = str(db.resolve())
    if key in _READY and db.exists():
        return sqlite3.connect(db)
    # First use: create the tables. This needs a write lock, so it is done once, not on every read
    # (it made each page load wait, most of all on Windows and on a Docker folder link).
    Path(runs_dir).mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db)
    con.executescript(SCHEMA)
    _READY.add(key)
    return con


def new_run(cfg: Config) -> str:
    run_id = base = datetime.now().strftime("%Y%m%d-%H%M%S")
    con = connect(cfg.runs_dir)
    n = 1
    while con.execute("SELECT 1 FROM runs WHERE id=?", (run_id,)).fetchone():   # two runs in the same second
        n += 1
        run_id = f"{base}-{n}"
    con.execute("INSERT INTO runs VALUES (?,?,?)", (run_id, datetime.now().isoformat(), cfg.model_dump_json()))
    con.commit()
    (Path(cfg.runs_dir) / run_id).mkdir(parents=True, exist_ok=True)
    return run_id


def save(cfg: Config, run_id: str, finding, ctx, verdict, decision, meta: dict) -> None:
    con = connect(cfg.runs_dir)
    con.execute("INSERT INTO results VALUES (?,?,?,?,?,?,?,?,?,?,?)", (
        run_id, finding.id, finding.model_dump_json(), ctx.model_dump_json() if ctx else None,
        verdict.model_dump_json() if verdict else None, decision.model_dump_json(), int(decision.verified),
        meta.get("tokens_in", 0), meta.get("tokens_out", 0), meta.get("cost", 0.0), meta.get("seconds", 0.0)))
    con.commit()


def save_raw(cfg: Config, run_id: str, raw_log: list) -> None:
    with open(Path(cfg.runs_dir) / run_id / "raw.jsonl", "w") as f:
        for item in raw_log:
            f.write(json.dumps(item) + "\n")


def latest_run(runs_dir: str) -> Optional[str]:
    row = connect(runs_dir).execute("SELECT id FROM runs ORDER BY created DESC LIMIT 1").fetchone()
    return row[0] if row else None


def load_run(runs_dir: str, run_id: str) -> List[dict]:
    con = connect(runs_dir)
    rows = con.execute("SELECT finding, context, verdict, decision, verified, tokens_in, tokens_out, cost, seconds "
                       "FROM results WHERE run_id=?", (run_id,)).fetchall()
    return [{"finding": json.loads(r[0]), "context": json.loads(r[1]) if r[1] else None,
             "verdict": json.loads(r[2]) if r[2] else None, "decision": json.loads(r[3]), "verified": bool(r[4]),
             "tokens_in": r[5], "tokens_out": r[6], "cost": r[7], "seconds": r[8]} for r in rows]


def load_config(runs_dir: str, run_id: str) -> dict:
    row = connect(runs_dir).execute("SELECT config FROM runs WHERE id=?", (run_id,)).fetchone()
    return json.loads(row[0]) if row else {}


def mark_partial(runs_dir: str, run_id: str, reason: str) -> None:
    """A scan that stopped early (spending limit or cancel). Its unchecked alerts were kept; never use it for evaluation."""
    con = connect(runs_dir)
    con.execute("INSERT OR REPLACE INTO run_status VALUES (?,?)", (run_id, reason))
    con.commit()


def partial_reason(runs_dir: str, run_id: str) -> Optional[str]:
    row = connect(runs_dir).execute("SELECT partial FROM run_status WHERE run_id=?", (run_id,)).fetchone()
    return row[0] if row else None


def save_review(runs_dir: str, run_id: str, finding_id: str, label: str, note: str = "") -> None:
    """A person's decision on one alert (from the GUI). Kept apart from the model's verdict, never mixed with it."""
    con = connect(runs_dir)
    con.execute("INSERT OR REPLACE INTO reviews (run_id, finding_id, label, note, updated) VALUES (?,?,?,?,?)",
                (run_id, finding_id, label, note, datetime.now().isoformat(timespec="seconds")))
    con.commit()


def load_reviews(runs_dir: str, run_id: str) -> dict:
    rows = connect(runs_dir).execute("SELECT finding_id, label, note, updated FROM reviews WHERE run_id=?", (run_id,))
    return {r[0]: {"label": r[1], "note": r[2], "updated": r[3]} for r in rows}


def list_runs(runs_dir: str) -> List[dict]:
    """One summary row per run, newest first: settings, alert count, hidden count, cost and time."""
    con = connect(runs_dir)
    out = []
    partial = dict(con.execute("SELECT run_id, partial FROM run_status").fetchall())
    # One pass over the results table for all runs (fast even on a slow Docker folder link on Windows)
    stats = {rid: rest for rid, *rest in con.execute(
        "SELECT run_id, COUNT(*), SUM(json_extract(decision, '$.action') = 'suppress'), COALESCE(SUM(cost), 0), "
        "COALESCE(SUM(seconds), 0) FROM results GROUP BY run_id")}
    for rid, created, conf in con.execute("SELECT id, created, config FROM runs ORDER BY created DESC").fetchall():
        c = json.loads(conf)
        n, hidden, cost, secs = stats.get(rid, (0, 0, 0, 0))
        out.append({"id": rid, "created": created[:16].replace("T", " "), "target": c.get("target", ""),
                    "provider": c.get("provider", ""), "model": "scanner only" if c.get("skip_judge") else c.get("model", ""),
                    "threshold": c.get("threshold"), "context_level": c.get("context_level"),
                    "alerts": n, "hidden": hidden or 0, "cost": round(cost, 4), "seconds": round(secs, 1),
                    "benchmark": bool(c.get("only_scored")), "partial": partial.get(rid)})
    return out


def average_call_cost(runs_dir: str, provider: str, model: Optional[str] = None) -> Optional[float]:
    """Average cost of one model call in earlier runs with this provider (and model, if given), for the cost estimate."""
    con = connect(runs_dir)
    q, args = "SELECT id FROM runs WHERE json_extract(config, '$.provider') = ?", [provider]
    if model:
        q, args = q + " AND json_extract(config, '$.model') = ?", args + [model]
    ids = [r[0] for r in con.execute(q, args)]
    if not ids:
        return None
    marks = ",".join("?" * len(ids))
    row = con.execute(f"SELECT AVG(cost) FROM results WHERE cost > 0 AND run_id IN ({marks})", ids).fetchone()  # nosec B608: only ? placeholders are inserted
    return row[0]
