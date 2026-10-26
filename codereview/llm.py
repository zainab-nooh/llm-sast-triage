"""Step 5: ask a model for a structured verdict. One interface, several providers.

Providers: mock (no key needed, for tests and demos), anthropic, openai, ollama (local).
Model names change often: set CODEREVIEW_MODEL in .env after checking the provider docs.
"""
import json
import os
import re
import urllib.request
from collections import Counter
from typing import Tuple

from pydantic import ValidationError

from .config import Config
from .models import Evidence, Verdict


# JSON Schema the model must follow (Claude "structured outputs"). It mirrors models.Verdict.
# Range checks (confidence between 0 and 1) are still done by Pydantic after the reply arrives.
VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "finding_id": {"type": "string"},
        "evidence": {"type": "array", "items": {
            "type": "object",
            "properties": {"file": {"type": "string"}, "lines": {"type": "string"}, "why": {"type": "string"}},
            "required": ["file", "lines", "why"], "additionalProperties": False}},
        "reasoning": {"type": "string"},
                "verdict": {"type": "string", "enum": ["confirmed", "likely_false_positive", "uncertain"]},
        "confidence_score": {"type": "number"},
        "sanitization_present": {"type": "boolean"},
        "attack_feasible": {"type": "boolean"},
        "policy_rule_id": {"type": "string"},
        "cwe": {"type": "string"},
        "suggested_fix": {"type": "string"},
    },
    "required": ["finding_id", "evidence", "reasoning", "sanitization_present", "attack_feasible",
                 "verdict", "confidence_score", "policy_rule_id", "cwe", "suggested_fix"],
    "additionalProperties": False,
}

# Models that accept the server-side refusal fallback (see the Claude API docs on refusals).
FALLBACK_MODELS = ("claude-opus-5-5", "claude-opus-5", "claude-fable-5-1", "claude-sonnet-5-5")

DECLINED = json.dumps({"verdict": "uncertain", "confidence_score": 0.0,
                       "reasoning": "The model declined to answer, so the alert is kept for a human."})


def _extract_json(text: str) -> str:
    text = text.strip()
    m = re.search(r"\{.*\}", text, re.S)
    return m.group(0) if m else text


def mock_complete(user: str) -> str:
    """Deterministic fake model so you can run and test everything without an API key."""
    code = re.search(r"<code>\n(.*?)\n</code>", user, re.S)
    body = code.group(1) if code else ""
    fid = re.search(r"- id: (\S+)", user)
    fid = fid.group(1) if fid else ""
    file = re.search(r"- file: (\S+),", user)
    file = file.group(1) if file else ""
    lines = [l for l in body.splitlines() if "|" in l]

    def find(token):
        for l in lines:
            if token in l:
                return int(l.split("|")[0].strip())
        return None

    n = find("execute(")
    safe = n is not None and any(t in body for t in ("?", "%s")) and "+" not in body.split("execute(")[1].split("\n")[0]
    if n and safe:
        v = dict(verdict="likely_false_positive", confidence_score=0.95, sanitization_present=True, attack_feasible=False,
                 evidence=[{"file": file, "lines": f"{n}", "why": "query uses placeholders"}], reasoning="Parameter binding keeps data out of the query.")
    elif n or find("shell=True") or find("eval("):
        k = n or find("shell=True") or find("eval(")
        v = dict(verdict="confirmed", confidence_score=0.9, sanitization_present=False, attack_feasible=True,
                 evidence=[{"file": file, "lines": f"{k}", "why": "untrusted data reaches the sink"}], reasoning="No protection found before the sink.")
    else:
        v = dict(verdict="uncertain", confidence_score=0.5, evidence=[], reasoning="Not enough context.")
    v.update(finding_id=fid, suggested_fix="Use parameterized queries or fixed argument lists.")
    return json.dumps(v)


def complete(system: str, user: str, cfg: Config) -> Tuple[str, int, int]:
    p = cfg.provider
    if p == "mock":
        return mock_complete(user), 0, 0
    if p == "anthropic":
        import anthropic
        client = anthropic.Anthropic()          # reads ANTHROPIC_API_KEY from the environment (.env)
        args = dict(model=cfg.model, max_tokens=16000, system=system,
                    messages=[{"role": "user", "content": user}],
                    output_config={"effort": cfg.effort,
                                   "format": {"type": "json_schema", "schema": VERDICT_SCHEMA}})
        # Current Claude models reject `temperature`, so it is not sent. Repeat runs measure the variation instead.
        if cfg.model in FALLBACK_MODELS:
            # Security questions can trip a safety filter. The fallback lets another model answer instead.
            r = client.beta.messages.create(betas=["server-side-fallback-2026-07-01"], fallbacks="default", **args)
        else:
            r = client.messages.create(**args)
        if r.stop_reason == "refusal":
            return DECLINED, r.usage.input_tokens, r.usage.output_tokens
        text = "".join(b.text for b in r.content if getattr(b, "type", "") == "text")
        return text, r.usage.input_tokens, r.usage.output_tokens
    if p == "openai":
        from openai import OpenAI
        r = OpenAI().chat.completions.create(model=cfg.model, temperature=0, response_format={"type": "json_object"},
                                             messages=[{"role": "system", "content": system}, {"role": "user", "content": user}])
        return r.choices[0].message.content, r.usage.prompt_tokens, r.usage.completion_tokens
    if p == "ollama":
        req = urllib.request.Request("http://localhost:11434/api/chat", method="POST",
                                     headers={"Content-Type": "application/json"},
                                     data=json.dumps({"model": cfg.model, "stream": False, "format": "json",
                                                      "options": {"temperature": 0,
                                                                  "num_ctx": int(os.getenv("CODEREVIEW_OLLAMA_CTX", 8192))},
                                                      "messages": [{"role": "system", "content": system},
                                                                   {"role": "user", "content": user}]}).encode())
        d = json.loads(urllib.request.urlopen(req, timeout=300).read())
        return d["message"]["content"], d.get("prompt_eval_count", 0), d.get("eval_count", 0)
    raise ValueError(f"Unknown provider: {p}")


def _one(system: str, user: str, cfg: Config, finding_id: str, raw_log: list) -> Tuple[Verdict, int, int]:
    tin = tout = 0
    prompt = user
    for attempt in range(3):  # retry on invalid JSON
        try:
            text, i, o = complete(system, prompt, cfg)
        except Exception as e:  # API down, timeout, model crash: fail open, keep the alert for a human
            raw_log.append({"finding_id": finding_id, "attempt": attempt, "error": repr(e)[:300]})
            return Verdict(finding_id=finding_id, verdict="uncertain", confidence_score=0.0,
                           reasoning=f"The model call failed ({type(e).__name__}), so the alert is kept for a human."), tin, tout
        tin, tout = tin + i, tout + o
        raw_log.append({"finding_id": finding_id, "attempt": attempt, "reply": text})
        try:
            v = Verdict.model_validate_json(_extract_json(text))
            v.finding_id = finding_id
            return v, tin, tout
        except (ValidationError, ValueError) as e:
            prompt = user + f"\n\nYour previous answer was invalid ({str(e)[:200]}). Return only valid JSON in the required shape."
    return Verdict(finding_id=finding_id, verdict="uncertain", confidence_score=0.0,
                   reasoning="Model output was not valid JSON after retries."), tin, tout


def judge(system: str, user: str, cfg: Config, finding_id: str, raw_log: list) -> Tuple[Verdict, dict]:
    """Return a Verdict and usage info. With votes > 1, take the majority verdict."""
    results = [_one(system, user, cfg, finding_id, raw_log) for _ in range(max(1, cfg.votes))]
    tin = sum(r[1] for r in results)
    tout = sum(r[2] for r in results)
    verdicts = [r[0] for r in results]
    top = Counter(v.verdict for v in verdicts).most_common(1)[0][0]
    chosen = [v for v in verdicts if v.verdict == top]
    best = max(chosen, key=lambda v: v.confidence_score)
    best.confidence_score = round(sum(v.confidence_score for v in chosen) / len(chosen), 3)
    if len(set(v.verdict for v in verdicts)) > 1:     # voters disagreed: be careful
        best.confidence_score = min(best.confidence_score, 0.5)
    cost = (tin * float(os.getenv("CODEREVIEW_PRICE_IN", 0)) + tout * float(os.getenv("CODEREVIEW_PRICE_OUT", 0))) / 1e6
    return best, {"tokens_in": tin, "tokens_out": tout, "cost": cost}
