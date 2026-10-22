"""The orchestrator: the whole system in one short loop. Each stage lives in its own module."""
import time
from pathlib import Path

from . import evaluate, gate, ingest, llm, policy, prompts, scanners, slicer, store, verifier
from .config import Config
from .models import Decision, Verdict


def run(cfg: Config) -> str:
    # ## Initialization and Setup 
    # Initilizes a new execution pass (a "run") in a database or file system and returns a unique run_id.
    run_id = store.new_run(cfg)
    # Creates a dedicated local directory path to hold outputs and logs for this specific execution. 
    run_dir = Path(cfg.runs_dir) / run_id

    # ## Scanning and Ingestion 
    # Executes underlying security tools (Bandit and Semgrep scanners) to analyze the target codebase and produce raw findings.
    sarif, bandit = scanners.run_all(cfg, run_dir)                       # 1. scan
    # Collects teh raw scanner outputs, Removes duplicates, filters out non-security bugs if requested (cfg.security_only), and narrows down the findings to specific types of vulnerabilities(cfg.only_cwes).
    findings = ingest.parse_all(sarif, bandit, cfg.target,              # 2. ingest, filter, merge copies
                                cfg.security_only, cfg.only_cwes)

    # ## Benchmark filtering and Throttling
    if cfg.only_scored:     # skip alerts the benchmark has no answer for: they cost money but change no metric
        truth = evaluate.load_truth(cfg.only_scored)
        findings = [f for f in findings if f.cwe and evaluate._key(f.file, f.cwe) in truth]
        # Cropping Results -> Slices the findings list to a maximum number of findings specified in the configuration (cfg.max_findings).
    if cfg.max_findings:
        findings = findings[: cfg.max_findings]
    raw_log: list = []
    for f in findings:
        t0 = time.time()
        # Saves scanner output as verified and skips to the next finding 
        if cfg.skip_judge:                                               # setup A: scanner only
            store.save(cfg, run_id, f, None, None, Decision(action="keep", reason="scanner only", verified=True), {})
            continue
        # Otherwise, executes AI triage workflow
        # (slicer.build()) -> Slices only snippets of code releven to vulnerability
        ctx = slicer.build(f, cfg.target, level=cfg.context_level)       # 3. slice context
        # (policy.for_cwe()) -> looks up specific evaluation rules and grading rubrics for CWE ID (Assigned)
        pol = policy.for_cwe(f.cwe, cfg.policy_path, cfg.rubrics_dir)    # 4. rules for this CWE
        # (prompts.build()) -> packages the vulnerability details , code snippets, and security rules --> structured system and user prompt 
        system, user = prompts.build(f, ctx, pol)                        # 4. assemble prompt
        # (llm.judge()) -> sends the structured prompt to the LLM (Acting as a security expert) for evaluation and receives a verdict (True Positive /False Positive ) and metadata
        verdict, meta = llm.judge(system, user, cfg, f.id, raw_log)      # 5. AI judges
        # (verifier.check()) -> it does not use the rules or rubrics. It checks one thing: that the lines the AI cites as evidence are really in the code it was shown. If not, the verdict becomes uncertain. So your “not making things up” idea is right, but the method is line checking.
        verdict, verified, why = verifier.check(verdict, ctx)            # 6. verify evidence
        # (gate.decide()) -> the two actions are suppress (hide) or keep, never delete. It suppresses only when the AI says likely_false_positive, the evidence is verified, and the confidence is at least 0.8. Everything else is kept. That’s what “fail-open” means.
        decision = gate.decide(verdict, verified, cfg.threshold)         # 7. fail-open gate
        meta["seconds"] = round(time.time() - t0, 3)
        # (store.save) -> Measures total execution duration for this specific finding and saves the code context, AI verdict, Final decision,  and metadata logs. 
        store.save(cfg, run_id, f, ctx, verdict, decision, meta)         # 8. store
    store.save_raw(cfg, run_id, raw_log)
    return run_id
