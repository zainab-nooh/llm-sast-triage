"""Step 9: HTML report from stored results."""
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import store


def build(runs_dir: str, run_id: str) -> Path:
    rows = store.load_run(runs_dir, run_id)
    groups = {"confirmed": [], "uncertain": [], "suppressed": [], "scanner_only": []}
    for r in rows:
        if r["verdict"] is None:
            groups["scanner_only"].append(r)
        elif r["decision"]["action"] == "suppress":
            groups["suppressed"].append(r)
        elif r["verdict"]["verdict"] == "confirmed":
            groups["confirmed"].append(r)
        else:
            groups["uncertain"].append(r)
    env = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"), autoescape=select_autoescape())
    html = env.get_template("report.html.j2").render(run_id=run_id, groups=groups, total=len(rows),
                                                     config=store.load_config(runs_dir, run_id))
    out = Path(runs_dir) / run_id / "report.html"
    out.write_text(html)
    return out
