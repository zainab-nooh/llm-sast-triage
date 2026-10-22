"""Optional stretch goal. Start it only after the pipeline runs end to end.
Run with:  streamlit run codereview/dashboard.py
"""
import pandas as pd
import streamlit as st

from codereview import store
from codereview.config import Config

cfg = Config()
st.title("Code review results")
con = store.connect(cfg.runs_dir)
runs = [r[0] for r in con.execute("SELECT id FROM runs ORDER BY created DESC")]
if not runs:
    st.info("No runs yet. Run: python -m codereview run sample_target")
    st.stop()
run_id = st.sidebar.selectbox("Run", runs)
rows = store.load_run(cfg.runs_dir, run_id)
df = pd.DataFrame([{
    "file": r["finding"]["file"], "line": r["finding"]["start_line"], "cwe": r["finding"]["cwe"],
    "tool": r["finding"]["tool"], "verdict": (r["verdict"] or {}).get("verdict", "scanner only"),
    "confidence": (r["verdict"] or {}).get("confidence_score"), "action": r["decision"]["action"]} for r in rows])
tab1, tab2 = st.tabs(["Overview", "Findings"])
with tab1:
    st.metric("Alerts", len(df))
    st.metric("Hidden as likely false positives", int((df.action == "suppress").sum()))
    st.bar_chart(df.verdict.value_counts())
with tab2:
    cwe = st.multiselect("CWE", sorted(df.cwe.dropna().unique()))
    view = df[df.cwe.isin(cwe)] if cwe else df
    st.dataframe(view, use_container_width=True)
    pick = st.selectbox("Details for row", list(view.index))
    r = rows[pick]
    st.write(r["verdict"]["reasoning"] if r["verdict"] else "No model verdict")
    if r["context"]:
        st.code("\n".join(f"{n:4d} | {t}" for n, t in r["context"]["lines"]), language="python")
