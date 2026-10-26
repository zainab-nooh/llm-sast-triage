"""Run settings. Every run saves its settings so experiments can be compared later."""
import os
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent.parent


def load_env(path: Path = ROOT / ".env") -> None:
    """Tiny .env loader (no extra dependency)."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


load_env()


def _default_semgrep_configs() -> List[str]:
    """Our own offline rules, plus the Semgrep community Python rules if scripts/get_data.sh downloaded them.
    Local rule files (instead of `--config auto`) keep every run reproducible and work without a Semgrep account."""
    configs = [str(ROOT / "rules")]
    community = ROOT / "data" / "semgrep-rules" / "python"
    if community.exists():
        configs.append(str(community))
    return configs


class Config(BaseModel):
    target: str = "."
    provider: str = Field(default_factory=lambda: os.getenv("CODEREVIEW_PROVIDER", "mock"))
    model: str = Field(default_factory=lambda: os.getenv("CODEREVIEW_MODEL", "claude-opus-5-5"))
    effort: str = Field(default_factory=lambda: os.getenv("CODEREVIEW_EFFORT", "medium"))  # Claude only: low | medium | high
    context_level: int = 2          # 1 function, 2 source-to-sink slice + guards, 3 = 2 + helper functions
    threshold: float = 0.8          # fail-open: suppress only at or above this confidence
    votes: int = 1                  # majority voting (use 3 on final runs only)
    helper_dirs: List[str] = Field(default_factory=list)  # other project folders to look up called helper functions in
    group: bool = True              # judge all alerts with the same CWE in the same function once, together
    skip_judge: bool = False        # setup A: scanner only
    max_findings: Optional[int] = None   # cost control while developing
    rubrics_dir: str = str(ROOT / "rubrics")
    policy_path: str = str(ROOT / "policy" / "policy.yaml")
    semgrep_configs: List[str] = Field(default_factory=_default_semgrep_configs)
    security_only: bool = True           # drop scanner alerts that have no CWE (code-quality rules)
    only_cwes: List[str] = Field(default_factory=list)   # e.g. ["CWE-89"] to judge one weakness type only
    only_scored: Optional[str] = None    # benchmark mode: path to the truth file; judge only alerts it can score
    sarif_path: Optional[str] = None     # use an existing scan instead of running Semgrep
    bandit_path: Optional[str] = None    # use an existing scan instead of running Bandit
    runs_dir: str = str(ROOT / "runs")
