# Targeted LLM-Assisted Secure Code Review (starter project)

A working skeleton for your graduation project. It already runs end to end with a **fake model** (no API key, no cost),
so you can see the whole flow on day one and then replace the pieces one by one.

```
scan (Semgrep + Bandit) -> ingest -> slice context -> add CWE rules -> model judges -> verify evidence -> fail-open gate -> store -> report
```

## 1. Set up (about 15 minutes)

You need Python 3.10 or newer and Git. These commands are for a bash terminal (Git Bash, MSYS2/UCRT64, WSL, macOS, Linux).

```bash
python -m venv .venv
source .venv/Scripts/activate     # Windows Python (Git Bash or MSYS2/UCRT64)
# source .venv/bin/activate       # WSL, macOS, Linux
# Check it worked: your prompt starts with (.venv), and `which python` points inside .venv
pip install -r requirements.txt
cp .env.example .env              # never commit .env
bash scripts/get_data.sh          # downloads the OWASP Benchmark and Semgrep rules into data/ (pinned versions)
```

## 2. See it work (offline, free)

```bash
pytest -q                                          # 13 tests should pass
python -m codereview run sample_target             # Semgrep + Bandit, fake model, gate, report
python -m codereview inspect app.py --prompt       # look inside: alerts, code slice and prompt for one file
```
Open the HTML report path that the `run` command prints.

## 3. Run on the OWASP Benchmark

```bash
B=data/benchmark-python
# Setup A, scanners only (about 1 minute). This is the baseline to beat.
python -m codereview run $B/testcode --scanner-only
python -m codereview evaluate $B/expectedresults-0.1.csv --cwe CWE-89

# Prototype: SQL injection only, with the fake model (free). Reuse the scan from the last run with --sarif/--bandit-json.
python -m codereview run $B/testcode --cwe CWE-89 --only-scored $B/expectedresults-0.1.csv
python -m codereview evaluate $B/expectedresults-0.1.csv --cwe CWE-89
```
`--only-scored` skips alerts the benchmark has no answer for, so you do not pay for them.

## 4. Use a real model

1. Set a **spending limit** in the Claude Console first.
2. Put `ANTHROPIC_API_KEY=...` in `.env`.
3. Start with 5 alerts and read the raw replies in `runs/<id>/raw.jsonl`:
```bash
python -m codereview run $B/testcode --cwe CWE-89 --only-scored $B/expectedresults-0.1.csv \
    --provider anthropic --model claude-haiku-5-5 --max-findings 5
```
The Claude call uses **structured outputs** (the reply must match a JSON schema) and sends no `temperature`,
because current Claude models reject it. Model names and prices change: check the official docs.

## 4b. Use the web app

```bash
python -m codereview serve
```

It prints a link like `http://127.0.0.1:8765/#t=...` and opens it in your browser. Only this computer can reach the
app, and the link holds a new session key each time you start it (do not share it). Press Ctrl+C to stop.
- **New scan:** type a folder, pick a model and the weakness types, press *Scan and estimate* (free, no AI), check
  the alert count and cost, then press *Start AI triage*. You can close the window; the scan keeps running.
- **Dashboard:** open issues, alerts waiting for you, noise removed by the AI, alerts per project and by type,
  and how many auto-ignored alerts you checked.
- **Issues:** filters, and for each alert the AI verdict, exploitability, the evidence it cited, the code it saw,
  a suggested fix, and buttons to record your own decision (saved apart from the AI verdict).
- **Scans:** every run (from the app or the command line) with cost and time, plus the HTML report, CSV and
  SARIF downloads. The OWASP view groups issues by OWASP Top 10:2025 category.

The app uses the evaluated settings (context level 2, threshold 0.6) and the same pipeline as the command line.

## 4c. Run it in Docker (no Python setup needed)

You need Docker Desktop (Windows/macOS) or Docker Engine (Linux), running. From the project folder:

```bash
docker compose up --build          # first time builds the image (a few minutes), later starts are quick
```

Open the link printed in the log (`http://127.0.0.1:8765/#t=...`). Stop with Ctrl+C, or `docker compose down`.

- **API key:** read from `.env` when the container starts. It is never copied into the image (`.dockerignore`
  excludes it), so the image can be shared without leaking it. No `.env` = mock model and Ollama still work.
- **Scanning a folder on your computer:** the container only sees the folder you hand it, read-only, as `/scan`.
  Type `/scan` in the app's folder box. Choose the folder when you start:
  `SCAN_DIR="C:/Users/you/projects/myapp" docker compose up` (use forward slashes on Windows).
  Without `SCAN_DIR` it mounts `sample_target`.
- **Public GitHub links** work as usual (git is inside the image).
- **Results** are saved in `./runs` on your computer, so scan history survives restarts and is shared with
  `python -m codereview serve`. Linux only: run `mkdir -p runs && chmod a+w runs` once (the app runs as user 10001).
- **Ollama:** the container reaches Ollama on your computer at `host.docker.internal:11434`.
- **After changing code or styling:** run `docker compose up --build` again so the image picks up the change.
  While styling, `python -m codereview serve` is quicker (refresh the page to see edits).
- Keep the port as 8765: the app only accepts requests addressed to `127.0.0.1:8765`.

Safety settings in `compose.yaml`: the port is published on 127.0.0.1 only (not your network), the app runs as a
normal user with no Linux capabilities, and the container file system is read-only except `/app/runs` and `/tmp`.
Scanner rules come from the copy inside the image, so scans work without internet (except GitHub links and Claude).

## 4d. Use it in CI (GitHub Actions)

`python -m codereview ci <folder>` is the pipeline version of a scan. It uses the evaluated settings (level 2,
threshold 0.6, effort low), writes `sast-triage.sarif`, adds a summary to the run page, marks Confirmed (error) and
Needs review (warning) alerts on the pull request's files, and exits with 1 when alerts match `--fail-on`
(`confirmed` by default; `review` or `never`). Without `ANTHROPIC_API_KEY` it runs scanner only and hides nothing.
`--max-cost` (default US$1) stops the AI; alerts it did not reach are kept.

This repository has two workflows in `.github/workflows/`:
- **Tests:** `pip check` and `pytest` on every push to main and every pull request.
- **SAST Triage:** checks the tool's own `codereview/` code on every pull request (and by hand from the Actions tab).
  To let Claude Haiku check the alerts, add the secret: Settings > Secrets and variables > Actions > New repository
  secret, name `ANTHROPIC_API_KEY`. Results: the run's summary page, annotations on the pull request, and the
  `sast-triage-results` artifact (SARIF + HTML report). To also fill the Security tab, set the repository variable
  `SAST_TRIAGE_CODE_SCANNING` to `true` (needs GitHub code scanning: free for public repositories).

Other repositories can use `action.yml` once this repository is public (see the example at the top of that file).

Security choices: actions are pinned to full commit ids, every job gets read-only permissions (only the optional
upload job may write security results), the key is given to one step only, workflow inputs reach scripts through
environment variables (no script injection), checkout does not keep the GitHub token, and the workflow uses
`pull_request`, so pull requests from forks never see the secret.

## 5. Folder map

| Path | What it is | Your job |
|---|---|---|
| `codereview/pipeline.py` | The orchestrator loop | Read it first. It is the whole system |
| `codereview/scanners.py`, `ingest.py` | Run scanners, read SARIF and JSON | Test on the benchmark; add fields you need |
| `codereview/slicer.py` | Context levels 1 to 3 | **Main piece of your work.** Improve and test it |
| `rubrics/*.yaml`, `policy/policy.yaml` | CWE micro-rubrics and the simulated policy | Write and refine the rules for your 5 to 6 CWEs |
| `codereview/prompts.py` | Prompt assembly | Compare a generic prompt with the rubric prompt |
| `codereview/llm.py` | Providers, retries, majority voting | Add the provider you will use; check model names |
| `codereview/verifier.py`, `gate.py` | Evidence check and fail-open rule | Tune the threshold on a dev subset |
| `codereview/store.py` | SQLite + JSONL storage | Keep every run's settings and raw replies |
| `codereview/evaluate.py` | Metrics and threshold sweep | Reads the OWASP answer key directly |
| `codereview/report.py`, `templates/` | HTML report | Polish for the demo |
| `codereview/server.py`, `web/` | Local web app: API (FastAPI) and the page (plain HTML, CSS, JavaScript) | `python -m codereview serve` |
| `rules/security.yml` | Local Semgrep rules (offline) | Add rules for simple policies |
| `tests/` | pytest tests with a fake model | Add a test with every new feature |
| `scripts/get_data.sh` | Downloads the benchmark and Semgrep rules at fixed versions | Run once |
| `docs/` | Weekly log, experiment log, thesis notes | Fill them in as you go |

## 6. Suggested order of work

1. Run the demo above and read `pipeline.py`, `slicer.py`, and `prompts.py`.
2. Run the scanner-only baseline on the benchmark and compare it with `docs/BASELINE_2026-10-14.md`.
3. Build the SQL injection prototype end to end (fake model first, then 5 real alerts, then all 21).
4. Write and refine the rubrics for the other five CWEs; check each one on a few benchmark files by hand.
5. Compare 2 or 3 models on 20 alerts, then run the full comparison (setups A, B, C), the threshold sweep and repeats.
6. Log every run in `docs/EXPERIMENT_LOG.csv`.

## 7. Honest status (14 October 2026)

- **Tested here:** all 13 tests pass (the 12 earlier ones also passed on Windows, Python 3.13 in UCRT64, on 14 Oct); the scanner-only baseline on the full benchmark; the whole pipeline on the
  benchmark with the fake model; the Claude request against a local stand-in server (request shape, structured output,
  no temperature, refusal handling).
- **Not tested here:** a real Claude, OpenAI or Ollama call (no API key was used), and Docker.
  Expect small fixes when you first use them. The OpenAI code still sends `temperature=0`, which some newer
  OpenAI models reject.
- The fake model is a simple rule of thumb for demos and tests. **Never report its numbers as results.**
- Semgrep produced no data-flow traces on the benchmark, so every slice comes from the code structure.
- Model confidence is self-reported, not a true probability. Tune the threshold on one part of the data and test on the rest.
- See `docs/NOTES_FOR_THESIS.md` for the decisions made so far and why.
