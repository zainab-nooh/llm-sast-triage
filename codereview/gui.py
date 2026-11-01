"""Local web interface (GUI) for the tool.   Start it with:   streamlit run codereview/gui.py

It runs on this computer only (.streamlit/config.toml sets the address to 127.0.0.1). It calls the same
pipeline as the command line with the frozen settings, so it changes nothing in how alerts are judged.
It adds three things: starting a scan without typing commands, reading results, and recording a person's
decision on each alert.

Security: code, file names and model text are untrusted, so they are always shown as plain text
(st.text / st.code), never as Markdown or HTML. The API key is read from .env and never shown.
"""
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # so "streamlit run" can import the package
from codereview import pipeline, report, store   # noqa: E402
from codereview.config import ROOT, Config       # noqa: E402

CWES = {"CWE-89": "SQL injection", "CWE-78": "OS command injection", "CWE-95": "Code injection (eval, exec)",
        "CWE-502": "Unsafe deserialization", "CWE-611": "XML external entities (XXE)",
        "CWE-614": "Cookie without the Secure flag"}
MODELS = {"Claude Haiku (cloud, uses your API key)": ("anthropic", "claude-haiku-5-5"),
          "Qwen3 14B (local with Ollama, code stays on this computer)": ("ollama", "qwen3:14b"),
          "Mock model (no AI, only for trying the interface)": ("mock", "mock")}
CONTEXT_LEVEL, THRESHOLD = 2, 0.6            # the settings frozen for the evaluation
FALLBACK_CALL_COST = 0.003                   # dollars per Claude call when there are no earlier runs to average
LABELS = ["Not reviewed", "Real vulnerability", "False positive", "Not sure"]
GROUPS = ["Confirmed", "Needs review", "Hidden"]
RUNS_DIR = os.getenv("CODEREVIEW_RUNS_DIR") or Config().runs_dir   # the env variable is only for tests


def group_of(row: dict) -> str:
    """Same three groups as the HTML report. Alerts the model did not judge are kept for review."""
    if row["decision"]["action"] == "suppress":
        return "Hidden"
    if row["verdict"] and row["verdict"]["verdict"] == "confirmed":
        return "Confirmed"
    return "Needs review"


def resolve_folder(text: str):
    p = Path(text.strip().strip('"')).expanduser()
    if not p.is_absolute():
        p = ROOT / p
    return p if p.is_dir() else None


# ---------------------------------------------------------------- New scan
def page_scan():
    st.header("New scan")
    missing = [t for t in ("semgrep", "bandit") if not shutil.which(t)]
    if missing:
        st.error(f"Not found: {', '.join(missing)}. Activate the project's virtual environment, then start the interface again.")

    folder_text = st.text_input("Folder to scan", placeholder="for example data/real/pygoat, or a full path")
    model_name = st.selectbox("Model", list(MODELS))
    provider, model = MODELS[model_name]
    if provider == "anthropic":
        if os.getenv("ANTHROPIC_API_KEY"):
            st.caption("API key found in .env. It is never shown here.")
        else:
            st.warning("No ANTHROPIC_API_KEY found. Add it to the .env file and start the interface again.")
    elif provider == "ollama":
        st.caption("Ollama must be running with the qwen3:14b model. A local run is free but much slower.")
    cwes = st.multiselect("Weakness types to check", list(CWES), default=list(CWES),
                          format_func=lambda c: f"{c}  {CWES[c]}")
    st.caption(f"Settings are fixed to the evaluated ones: context level {CONTEXT_LEVEL}, confidence threshold "
               f"{THRESHOLD}. An alert is only hidden when the AI is confident it is a false positive; "
               "everything else is kept for a person.")

    folder = resolve_folder(folder_text) if folder_text else None
    if folder_text and not folder:
        st.error("That folder does not exist.")
    choice = (str(folder), tuple(cwes), provider, model)
    plan = st.session_state.get("plan")
    if plan and plan["choice"] != choice:            # the user changed something: the old count no longer applies
        st.session_state.pop("plan")
        plan = None

    if st.button("1. Scan and estimate the cost", disabled=not (folder and cwes) or bool(missing)):
        scan_dir = Path(RUNS_DIR) / "gui-scans" / datetime.now().strftime("%Y%m%d-%H%M%S")
        scan_dir.mkdir(parents=True, exist_ok=True)
        with st.spinner("Running Semgrep and Bandit..."):
            sarif, bandit, groups = pipeline.collect(Config(target=str(folder), only_cwes=cwes, runs_dir=RUNS_DIR), scan_dir)
        plan = {"choice": choice, "sarif": str(sarif) if sarif else None, "bandit": str(bandit) if bandit else None,
                "alerts": sum(len(g) for g in groups), "groups": len(groups)}
        st.session_state["plan"] = plan

    if not plan:
        return
    if plan["alerts"] == 0:
        st.success("The scanners found no alerts of these types. Nothing to check.")
        return
    if provider == "anthropic":
        per_call = store.average_call_cost(RUNS_DIR, "anthropic") or FALLBACK_CALL_COST
        cost = f"about ${plan['groups'] * per_call:.2f} (${per_call:.4f} per check, from your earlier runs)"
    else:
        cost = "$0 (no paid API)"
    st.info(f"{plan['alerts']} alerts in {plan['groups']} groups (alerts in the same function are checked together). "
            f"Estimated cost: {cost}.")
    if st.button("2. Ask the AI to check the alerts", type="primary"):
        cfg = Config(target=str(folder), provider=provider, model=model, context_level=CONTEXT_LEVEL, runs_dir=RUNS_DIR,
                     threshold=THRESHOLD, only_cwes=cwes, sarif_path=plan["sarif"], bandit_path=plan["bandit"])
        bar = st.progress(0.0, text="Starting...")

        def progress(done, total, finding):
            bar.progress(done / total, text=f"Checking group {done + 1} of {total}: {Path(finding.file).name} line {finding.start_line}")

        run_id = pipeline.run(cfg, progress=progress)
        report.build(RUNS_DIR, run_id)
        bar.progress(1.0, text="Done")
        st.session_state.pop("plan", None)
        st.session_state["run_id"] = run_id
        st.session_state["goto"] = "Results"
        st.rerun()


# ---------------------------------------------------------------- Results
def show_detail(run_id: str, r: dict, review: dict):
    f, v, d = r["finding"], r["verdict"] or {}, r["decision"]
    st.subheader("Alert details")
    st.text(f"{f['file']}:{f['start_line']}   {f['cwe']}   {f['tool']} rule {f['rule_id']}")
    st.text(f"Scanner says: {f['message']}")
    left, right = st.columns([3, 2])
    with left:
        ctx = r["context"]
        if ctx and ctx["lines"]:
            flagged = range(f["start_line"], f["end_line"] + 1)
            code = "\n".join(f"{'>>' if n in flagged else '  '} {n:5d} | {text}" for n, text in ctx["lines"])
            st.caption("Code shown to the AI (>> marks the flagged line; lines that do not matter are left out)")
            st.code(code, language="python")
            if ctx.get("helpers"):
                st.caption("Helper code from other files")
                st.code("\n".join(f"{hf}:{n} | {text}" for hf, n, text in ctx["helpers"]), language="python")
        else:
            st.caption("No code context: this alert was not sent to the AI.")
    with right:
        if v:
            st.metric("AI verdict", v["verdict"].replace("_", " "), f"confidence {v['confidence_score']:.2f}",
                      delta_color="off")
        st.text(f"Decision: {d['action']} ({d['reason']})")
        if v.get("reasoning"):
            st.caption("Why")
            st.text(v["reasoning"])
        for e in v.get("evidence", []):
            st.caption(f"Evidence, lines {e['lines']}")
            st.text(e.get("why", ""))
        if v.get("suggested_fix"):
            st.caption("Suggested fix")
            st.text(v["suggested_fix"])

    with st.form(key=f"review-{run_id}-{f['id']}"):
        st.caption("Your decision (saved with this run; it never changes the AI's verdict)")
        current = review.get("label", "Not reviewed")
        label = st.radio("Decision", LABELS, index=LABELS.index(current) if current in LABELS else 0,
                         horizontal=True, label_visibility="collapsed")
        note = st.text_area("Note (optional)", value=review.get("note", ""))
        if st.form_submit_button("Save decision"):
            store.save_review(RUNS_DIR, run_id, f["id"], label, note)
            st.toast("Saved")
            st.rerun()


def page_results():
    st.header("Results")
    runs = store.list_runs(RUNS_DIR)
    if not runs:
        st.info("No runs yet. Start one on the New scan page.")
        return
    names = {r["id"]: f"{r['id']}   {Path(r['target']).name}   {r['model']}   ({r['alerts']} alerts)" for r in runs}
    ids = list(names)
    wanted = st.session_state.get("run_id")
    run_id = st.selectbox("Run", ids, index=ids.index(wanted) if wanted in ids else 0, format_func=names.get)
    st.session_state["run_id"] = run_id
    rows = store.load_run(RUNS_DIR, run_id)
    reviews = store.load_reviews(RUNS_DIR, run_id)
    if not rows:
        st.info("This run has no alerts.")
        return
    df = pd.DataFrame([{
        "group": group_of(r), "file": r["finding"]["file"], "line": r["finding"]["start_line"],
        "type": r["finding"]["cwe"], "verdict": (r["verdict"] or {}).get("verdict", "not judged"),
        "confidence": (r["verdict"] or {}).get("confidence_score"),
        "your decision": reviews.get(r["finding"]["id"], {}).get("label", "Not reviewed")} for r in rows])

    counts = df.group.value_counts()
    cols = st.columns(5)
    cols[0].metric("Alerts", len(df))
    for col, g in zip(cols[1:4], GROUPS):
        col.metric(g, int(counts.get(g, 0)))
    cols[4].metric("Reviewed by you", int((df["your decision"] != "Not reviewed").sum()))

    show = st.radio("Show", ["All"] + GROUPS, horizontal=True)
    f1, f2, f3 = st.columns(3)
    types = f1.multiselect("Type", sorted(df.type.dropna().unique()))
    file_part = f2.text_input("File name contains")
    decision = f3.selectbox("Your decision", ["Any"] + LABELS)
    view = df if show == "All" else df[df.group == show]
    if types:
        view = view[view.type.isin(types)]
    if file_part:
        view = view[view.file.str.contains(file_part, case=False, regex=False)]
    if decision != "Any":
        view = view[view["your decision"] == decision]
    if view.empty:
        st.info("No alerts match.")
    else:
        event = st.dataframe(view, hide_index=True, width="stretch", on_select="rerun",
                             selection_mode="single-row", key=f"table-{run_id}-{show}")
        picked = event.selection.rows
        st.caption("Click a row to see its details." if not picked else "")
        pos = view.index[picked[0]] if picked else view.index[0]
        show_detail(run_id, rows[pos], reviews.get(rows[pos]["finding"]["id"], {}))

    st.divider()
    st.subheader("Export")
    out = df.copy()
    out["note"] = [reviews.get(r["finding"]["id"], {}).get("note", "") for r in rows]
    out["reason"] = [r["decision"]["reason"] for r in rows]
    c1, c2 = st.columns(2)
    c1.download_button("Download CSV (with your decisions)", out.to_csv(index=False).encode("utf-8"),
                       file_name=f"results-{run_id}.csv", mime="text/csv")
    html = report.build(RUNS_DIR, run_id).read_bytes()
    c2.download_button("Download HTML report", html, file_name=f"report-{run_id}.html", mime="text/html")


# ---------------------------------------------------------------- History
def page_history():
    st.header("Run history")
    runs = store.list_runs(RUNS_DIR)
    if not runs:
        st.info("No runs yet.")
        return
    df = pd.DataFrame(runs)[["id", "created", "target", "model", "context_level", "threshold", "alerts", "hidden", "cost", "seconds"]]
    df["target"] = df.target.map(lambda t: Path(t).name)
    st.dataframe(df, hide_index=True, width="stretch",
                 column_config={"cost": st.column_config.NumberColumn("cost ($)", format="%.4f"),
                                "seconds": st.column_config.NumberColumn("time (s)", format="%.0f")})
    st.caption("Runs made from the command line appear here too. Pick one on the Results page to read it.")


def main():
    st.set_page_config(page_title="LLM SAST triage", layout="wide")
    if "goto" in st.session_state:                     # move to another page after a scan finishes
        st.session_state["page"] = st.session_state.pop("goto")
    st.sidebar.title("LLM SAST triage")
    st.sidebar.caption("Checks static-analysis alerts with an AI and hides only the confident false positives.")
    page = st.sidebar.radio("Page", ["New scan", "Results", "History"], key="page")
    {"New scan": page_scan, "Results": page_results, "History": page_history}[page]()


main()
