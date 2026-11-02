#!/usr/bin/env bash
# FINAL RUN on the untouched test half, with the frozen settings (context 2, helpers, effort low).
# Usage:  bash final_run.sh haiku     (main result, about $0.06)
#         bash final_run.sh sonnet    (secondary comparison, about $1)
# Each weakness type is run separately, exactly like the dev runs. Results are scored at 0.6 and 0.8 from the
# same stored verdicts (no extra AI calls). Everything is saved in results-test/<model>/.
set -euo pipefail
case "${1:-}" in
  haiku)  MODEL=claude-haiku-5-5 ;;
  sonnet) MODEL=claude-sonnet-5-5 ;;
  *) echo "Usage: bash final_run.sh haiku|sonnet"; exit 1 ;;
esac
B=data/benchmark-python; T=data/splits/test.csv; OUT="results-test/$1"
export CODEREVIEW_EFFORT=low
[ -f "$T" ] && [ -d "$B/testcode" ] && [ -d "$B/helpers" ] || { echo "Missing data: run  bash scripts/get_data.sh  first"; exit 1; }
mkdir -p "$OUT"
{ echo "model=$MODEL"; echo "commit=$(git rev-parse --short HEAD)"; echo "tag=$(git describe --tags --always)"; echo "started=$(date)"; } > "$OUT/info.txt"
for C in CWE-89 CWE-78 CWE-95 CWE-502 CWE-611 CWE-614; do
  echo; echo "=== $C ($MODEL) ==="
  python -m codereview run "$B/testcode" --provider anthropic --model "$MODEL" --context 2 --threshold 0.6 \
      --helpers "$B/helpers" --only-scored "$T" --cwe "$C"
  RID=$(python -c "from codereview import store; from codereview.config import Config; print(store.latest_run(Config().runs_dir))")
  echo "$C run=$RID" >> "$OUT/info.txt"
  for TH in 0.6 0.8; do
    python -m codereview evaluate "$T" --run-id "$RID" --threshold "$TH" --cwe "$C" > "$OUT/$C-$TH.json"
  done
done
echo "finished=$(date)" >> "$OUT/info.txt"
python - "$OUT" <<'PY'
import json, sys, pathlib
out = pathlib.Path(sys.argv[1]); lines = []
for th in ("0.6", "0.8"):
    tot = {"s": dict(tp=0, fp=0, fn=0, tn=0), "p": dict(tp=0, fp=0, fn=0, tn=0)}; cost = secs = 0
    lines.append(f"\nThreshold {th}:  CWE      scanner FP  removed  real  lost  precision(tool)")
    for f in sorted(out.glob(f"*-{th}.json")):
        d = json.loads(f.read_text()); s, p = d["scanner_only"], d["pipeline"]
        for k in tot["s"]: tot["s"][k] += s[k]; tot["p"][k] += p[k]
        cost += d["cost"] or 0; secs += d["seconds"] or 0
        lines.append(f"  {f.name.split('-0')[0]:>8} {s['fp']:>11} {s['fp']-p['fp']:>8} {s['tp']:>5} {p['fn']-s['fn']:>5} {p['precision']:>10}")
    s, p = tot["s"], tot["p"]
    prec = lambda x: round(x["tp"] / (x["tp"] + x["fp"]), 3) if x["tp"] + x["fp"] else 0
    lines.append(f"  {'TOTAL':>8} {s['fp']:>11} {s['fp']-p['fp']:>8} {s['tp']:>5} {p['fn']-s['fn']:>5} {prec(p):>10}"
                 f"   (scanner precision {prec(s)}; AI cost ${cost:.3f}; {secs:.0f} s)")
text = "\n".join(lines); print(text); (out / "summary.txt").write_text(text + "\n")
PY
echo; echo "Saved in $OUT/ (summary.txt, info.txt, one JSON per weakness and threshold). Send me summary.txt and info.txt."
