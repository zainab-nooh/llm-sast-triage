# Decisions and limits to write down as you go (saves time in December)

## Facts measured on 14 October 2026 (starting point, before any model was used)

Setup: OWASP Benchmark for Python v0.1 (commit f129148, 1,230 test files), Bandit 1.9.4,
Semgrep 1.180.0 with the community Python rules (commit 9bbf021, 371 rules, run offline).
Full table: `docs/BASELINE_2026-10-14.md`.

- **Semgrep gave no data-flow traces at all** (0 of 3,526 alerts, also with `--dataflow-traces`).
  Bandit never gives traces. So every slice is built from the code structure. This supports making
  the data-flow requirement a Should, as the proposal already says.
- **The scanners miss some categories completely** (path traversal 3% recall, XSS 0%, XPath, LDAP and
  trust-boundary 0%). An AI filter can only remove false alarms; it cannot find what was never flagged.
  So these categories are outside the evaluation, and this is a stated limit.
- **Six CWEs chosen for the evaluation** because the scanners flag every real case there (recall 1.0)
  but also many false ones: SQL injection (89), OS command injection (78), code injection (94/95),
  unsafe deserialization (502), XXE (611) and insecure cookies (614).
  Together: 88 real and 98 false alarms (precision 0.47). This is setup A, the baseline to beat.
- **Scanner labels needed correcting.** Bandit labels eval/exec as CWE-78 and XML parsing as CWE-20;
  two Semgrep "tainted-sql-string" rules are tagged CWE-915 and CWE-704. The corrections are in
  `codereview/ingest.py` (the original label is kept in `scanner_cwe`).
- **The benchmark uses different CWE numbers for two categories** (94 instead of 95, 328 instead of 327).
  These are mapped only when scoring (`codereview/evaluate.py`, `SCORING_ALIASES`).

## To fill in later

- Why Python only:
- Why Semgrep + Bandit:
- How the policy was written (simulated policy from OWASP Top 10:2025 / CWE):
- What the fail-open threshold is and how I tuned it (dev subset vs test subset):
- Which model(s) I compared and why I picked one (cost, speed, quality):
- Known limits: benchmark is easier than real code, possible training-data contamination, model confidence is
  not calibrated, no source-to-sink trace from the scanners, scoring is per file (one verdict per test case).
- Security of the tool: prompt injection tests, secret redaction, spending limit.
