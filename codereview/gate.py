"""Step 7: fail-open gate. An alert is hidden only when the model is confident AND the evidence checked out."""
from .models import Decision, Verdict


def decide(verdict: Verdict, verified: bool, threshold: float) -> Decision:
    if verdict.verdict == "likely_false_positive" and verified and verdict.confidence_score >= threshold:
        return Decision(action="suppress", reason=f"likely false positive, confidence {verdict.confidence_score:.2f} >= {threshold}", verified=verified)
    why = "kept for human review: "
    if verdict.verdict != "likely_false_positive":
        why += f"verdict is {verdict.verdict}"
    elif not verified:
        why += "evidence could not be verified"
    else:
        why += f"confidence {verdict.confidence_score:.2f} below threshold {threshold}"
    return Decision(action="keep", reason=why, verified=verified)
