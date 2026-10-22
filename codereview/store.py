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
"""


def connect(runs_dir: str) -> sqlite3.Connection:
    Path(runs_dir).mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(Path(runs_dir) / "results.db")
    con.executescript(SCHEMA)
    return con


def new_run(cfg: Config) -> str:
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    con = connect(cfg.runs_dir)
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
