"""The orchestrator: the whole system in one short loop. Each stage lives in its own module."""
import time
from pathlib import Path

from . import evaluate, gate, ingest, llm, policy, prompts, scanners, slicer, store, verifier
from .config import Config
from .models import Decision, Verdict


def run(cfg: Config) -> str:
    run_id = store.new_run(cfg)
    run_dir = Path(cfg.runs_dir) / run_id
    sarif, bandit = scanners.run_all(cfg, run_dir)                       # 1. scan
    findings = ingest.parse_all(sarif, bandit, cfg.target,              # 2. ingest, filter, merge copies
                                cfg.security_only, cfg.only_cwes)
    if cfg.only_scored:     # skip alerts the benchmark has no answer for: they cost money but change no metric
        truth = evaluate.load_truth(cfg.only_scored)
        findings = [f for f in findings if f.cwe and evaluate._key(f.file, f.cwe) in truth]
    if cfg.max_findings:
        findings = findings[: cfg.max_findings]
    raw_log: list = []
    groups: dict = {}                                                    # 2b. group alerts by file, function, CWE
    for f in findings:
        fn = slicer.function_key(f, cfg.target) if cfg.group else None
        key = (f.file, fn, f.cwe) if fn is not None else (f.id,)
        groups.setdefault(key, []).append(f)
    for group in groups.values():
        t0 = time.time()
        f, others = group[0], group[1:]
        if cfg.skip_judge:                                               # setup A: scanner only
            for g in group:
                store.save(cfg, run_id, g, None, None, Decision(action="keep", reason="scanner only", verified=True), {})
            continue
        ctx = slicer.merge([slicer.build(g, cfg.target, level=cfg.context_level, helper_dirs=cfg.helper_dirs) for g in group])  # 3. slice context
        pol = policy.for_cwe(f.cwe, cfg.policy_path, cfg.rubrics_dir)    # 4. rules for this CWE
        system, user = prompts.build(f, ctx, pol, others)                # 4. assemble prompt
        verdict, meta = llm.judge(system, user, cfg, f.id, raw_log)      # 5. AI judges
        verdict, verified, why = verifier.check(verdict, ctx)            # 6. verify evidence
        decision = gate.decide(verdict, verified, cfg.threshold)         # 7. fail-open gate
        meta["seconds"] = round(time.time() - t0, 3)
        store.save(cfg, run_id, f, ctx, verdict, decision, meta)         # 8. store (the cost is counted once)
        for g in others:
            store.save(cfg, run_id, g, ctx, verdict, decision, {})
    store.save_raw(cfg, run_id, raw_log)
    return run_id