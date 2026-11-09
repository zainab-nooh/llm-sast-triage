"""Build the sample data for the public read-only demo from your own runs.

    python scripts/make_demo_data.py                 # latest complete Claude Haiku scan of each real project
    python scripts/make_demo_data.py --run 20261104-150528 --run 20261108-215200   # or pick scans yourself

It copies the chosen scans from runs/results.db into demo/results.db and removes everything that points at
your computer: folder paths (C:\\Users\\...), the runs folder, and your notes on decisions (labels are kept).
Benchmark runs are skipped, so no benchmark answers end up in the demo. Check the printed list before you
publish demo/, and only include public open-source projects.
"""
import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path

HOME = re.compile(r"(?i)([A-Z]:)?[\\/]+(Users|home)[\\/]+[^\\/\s\"']+")   # C:\Users\name or /home/name


def short_target(target: str) -> str:
    """'C:\\Users\\me\\...\\app-repos\\owner\\latest\\pygoat' -> '/demo/latest/pygoat' (the project name stays the same)."""
    parts = [p for p in re.split(r"[\\/]+", target) if p]
    return "/demo/" + "/".join(parts[-2:])


def clean(text, targets: dict, runs_dir: str):
    if text is None:
        return None
    for old, new in sorted(targets.items(), key=lambda kv: -len(kv[0])):
        for variant in {old, old.replace("\\", "/"), old.replace("\\", "\\\\")}:
            text = text.replace(variant, new)
    for variant in {runs_dir, runs_dir.replace("\\", "/"), runs_dir.replace("\\", "\\\\")}:
        if variant:
            text = text.replace(variant, "/demo/runs")
    return HOME.sub("~", text)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", default="runs", help="your results folder (default: runs)")
    ap.add_argument("--out", default="demo", help="where to write the demo data (default: demo)")
    ap.add_argument("--run", action="append", default=[], help="a scan id to include (repeat for more)")
    ap.add_argument("--model", default="claude-haiku-5-5", help="model of the scans picked automatically")
    a = ap.parse_args()

    src = sqlite3.connect(Path(a.runs) / "results.db")
    runs = []
    partial = {r for (r,) in src.execute("SELECT run_id FROM run_status")}
    for rid, created, conf in src.execute("SELECT id, created, config FROM runs ORDER BY created DESC"):
        c = json.loads(conf)
        if a.run:
            if rid in a.run:
                runs.append((rid, created, c))
        elif (c.get("model") == a.model and not c.get("skip_judge") and not c.get("only_scored")
              and rid not in partial and "benchmark" not in c.get("target", "").lower()
              and not any(re.split(r"[\\/]+", c.get("target", ""))[-1] == re.split(r"[\\/]+", x[2].get("target", ""))[-1] for x in runs)):
            runs.append((rid, created, c))
    if not runs:
        print("No scans matched. Use --run <scan id> to pick them (ids are shown on the Scan history page).")
        return 1

    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    db = out / "results.db"
    if db.exists():
        db.unlink()
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from codereview import store                          # creates the same tables the app expects
    dst = store.connect(str(out))
    targets = {c.get("target", ""): short_target(c.get("target", "")) for _, _, c in runs if c.get("target")}
    runs_dir = str(Path(a.runs).resolve())
    keep = ("target", "provider", "model", "threshold", "context_level", "skip_judge", "only_cwes")
    print("Demo scans:")
    for rid, created, c in runs:
        cfg = {k: c[k] for k in keep if k in c}
        cfg["target"] = targets.get(c.get("target", ""), "/demo/project")
        dst.execute("INSERT INTO runs VALUES (?,?,?)", (rid, created, json.dumps(cfg)))
        rows = src.execute("SELECT * FROM results WHERE run_id=?", (rid,)).fetchall()
        for r in rows:
            dst.execute(f"INSERT INTO results VALUES ({','.join('?' * len(r))})",
                        [clean(v, targets, runs_dir) if isinstance(v, str) else v for v in r])
        for r in src.execute("SELECT run_id, finding_id, label, updated FROM reviews WHERE run_id=?", (rid,)):
            dst.execute("INSERT INTO reviews VALUES (?,?,?,?,?)", (r[0], clean(r[1], targets, runs_dir), r[2], "", r[3]))
        for r in src.execute("SELECT run_id, finding_id, label, at FROM review_log WHERE run_id=?", (rid,)):
            dst.execute("INSERT INTO review_log VALUES (?,?,?,?,?)", (r[0], clean(r[1], targets, runs_dir), r[2], "", r[3]))
        print(f"  {rid}  {cfg['target'].split('/')[-1]:<20} {len(rows):>4} alerts  {c.get('model')}")
    dst.commit()
    leftovers = [t for (t,) in dst.execute("SELECT finding || context || verdict || decision FROM results")
                 if t and re.search(r"(?i)[A-Z]:\\\\|/Users/|/home/", t)]
    print(f"Written to {db}. " + (f"WARNING: {len(leftovers)} results still mention a local path, check them."
                                   if leftovers else "No local paths left."))
    return 0


if __name__ == "__main__":
    sys.exit(main())
