"""Typed data passed between pipeline stages."""
from typing import List, Literal, Optional, Tuple

from pydantic import BaseModel, Field


class Finding(BaseModel):
    id: str
    tool: str                      # semgrep or bandit
    rule_id: str
    cwe: Optional[str] = None      # normalized like "CWE-89"
    file: str                      # path relative to the scanned folder
    start_line: int
    end_line: int
    message: str
    severity: str = "unknown"
    trace: List[str] = Field(default_factory=list)   # "file:line" steps, source to sink, if available
    scanner_cwe: Optional[str] = None  # the CWE exactly as the scanner reported it, before any correction
    also_reported_by: List[str] = Field(default_factory=list)  # other rules that flagged the same line and CWE


class Evidence(BaseModel):
    file: str
    lines: str                     # "41-47" or "41"
    why: str = ""


class Verdict(BaseModel):
    finding_id: str = ""
    verdict: Literal["confirmed", "likely_false_positive", "uncertain"]
    confidence_score: float = Field(ge=0.0, le=1.0)
    sanitization_present: bool = False
    attack_feasible: bool = True
    policy_rule_id: Optional[str] = None
    cwe: Optional[str] = None
    evidence: List[Evidence] = Field(default_factory=list)
    reasoning: str = ""
    suggested_fix: str = ""


class Context(BaseModel):
    level: int
    file: str
    lines: List[Tuple[int, str]]   # (line number, text)
    note: str = ""

    def numbers(self) -> List[int]:
        return [n for n, _ in self.lines]

    def render(self) -> str:
        out, prev = [], None
        for n, text in self.lines:
            if prev is not None and n > prev + 1:
                out.append("     | ...")
            out.append(f"{n:4d} | {text}")
            prev = n
        return "\n".join(out)


class Decision(BaseModel):
    action: Literal["suppress", "keep"]
    reason: str
    verified: bool = True
