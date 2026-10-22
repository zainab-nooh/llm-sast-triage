# What changed from the first starter (14 October 2026)

Every change below came from running the starter on the real OWASP Benchmark for Python, not from guessing.

| File | Change | Why |
|---|---|---|
| `codereview/slicer.py` | Level 2 now follows values through objects (`conf.set(..., param)` then `conf.get(...)`), for-loops and with-blocks, repeats until nothing new is found, and follows the query forward and then backward | On benchmark files the old slice left out where the user value came from, so the model could not judge |
| `codereview/ingest.py` | Corrects wrong CWE labels (Bandit eval/exec, XML, yaml; two Semgrep SQL rules), keeps the original label, drops non-security and import-only alerts, merges copies of the same alert | Wrong labels picked the wrong rubric; copies and import lines cost money and add nothing |
| `codereview/llm.py` | Claude call uses structured outputs (JSON schema), no `temperature`, refusal handled as "uncertain", server-side fallback on supported models | The installed SDK has no `temperature` argument (the old call would crash) and current models reject it |
| `codereview/evaluate.py` | Reads the OWASP answer key directly, maps CWE 95 to 94 and 327 to 328 for scoring, can score chosen CWEs only | The benchmark numbers some CWEs differently from the scanners |
| `codereview/pipeline.py`, `cli.py`, `config.py` | New options `--cwe`, `--only-scored`, `--effort`; local Semgrep community rules used by default | Run one CWE for the prototype; do not pay for alerts that cannot be scored; reproducible scans offline |
| `codereview/scanners.py` | Semgrep runs with `--no-git-ignore --disable-version-check` | `data/` is git-ignored and would otherwise be skipped |
| `codereview/prompts.py` | Two rules added: follow the value backwards (constant branches), and cite only line numbers shown | Common reasons for false alarms in the benchmark; stops invented line numbers |
| `rubrics/`, `policy/policy.yaml`, `rules/security.yml` | Rubrics for CWE-95, 611, 614; policy rules SEC-011 and SEC-012; OWASP Top 10:2025 categories | Match the six CWEs chosen from the baseline |
| `scripts/get_data.sh` | New: downloads benchmark and rules at fixed commits | Same data every time |
| `requirements.txt` | Exact versions | Repeatable results |
| `tests/` | 6 new tests (13 in total) | One test per fix; the two slicer tests fail on the old slicer |
| `docs/` | Baseline table, thesis notes, first experiment-log row | Real numbers from day one |
| `codereview/cli.py` | New `inspect` command: shows the alerts, code slice and prompt for one file, free | To see inside each step while learning and debugging |
