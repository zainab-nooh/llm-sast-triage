"""Step 6: check that the model's evidence is real. Failed checks downgrade the verdict to uncertain."""
from typing import Tuple

from .models import Context, Verdict


def _parse_lines(spec: str):
    spec = str(spec).strip()
    try:
        if "-" in spec:
            a, b = spec.split("-", 1)
            return int(a), int(b)
        return int(spec), int(spec)
    except ValueError:
        return None


def check(verdict: Verdict, ctx: Context) -> Tuple[Verdict, bool, str]:
    """Return (possibly downgraded verdict, verified?, reason)."""
    if verdict.verdict == "uncertain":
        return verdict, True, "uncertain verdicts need no evidence"
    shown = set(ctx.numbers())
    if not verdict.evidence:
        reason = "no evidence cited"
    else:
        reason = ""
        for ev in verdict.evidence:
            span = _parse_lines(ev.lines)
            if span is None or span[0] > span[1]:
                reason = f"bad line reference: {ev.lines}"
            elif span[0] not in shown or span[1] not in shown:
                # A range may jump over lines the slice left out ("..."), but it must start and end on shown lines.
                reason = f"cited lines {ev.lines} do not start and end on lines that were shown"
            if reason:
                break
    if reason:
        verdict = verdict.model_copy(update={"verdict": "uncertain", "confidence_score": min(verdict.confidence_score, 0.4),
                                             "reasoning": f"[verifier: {reason}] " + verdict.reasoning})
        return verdict, False, reason
    return verdict, True, "evidence verified"
