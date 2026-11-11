"""Step 1: run Semgrep and Bandit and save their raw output."""
import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional, Tuple

from .config import Config


def run_semgrep(target: str, out_file: Path, configs) -> Optional[Path]:
    exe = shutil.which("semgrep")
    if not exe:
        print("semgrep not found: install it or pass --sarif with an existing file")
        return None
    # --no-git-ignore: also scan folders that .gitignore hides (data/ is ignored in this project)
    cmd = [exe, "scan", "--sarif", "--output", str(out_file), "--metrics=off", "--quiet",
           "--disable-version-check", "--no-git-ignore"]
    # Optional limits for small hosts (the online demo has 512 MB): fewer parallel jobs, a memory cap
    if os.environ.get("CODEREVIEW_SEMGREP_JOBS"):
        cmd += ["--jobs", os.environ["CODEREVIEW_SEMGREP_JOBS"]]
    if os.environ.get("CODEREVIEW_SEMGREP_MAX_MEMORY"):
        cmd += ["--max-memory", os.environ["CODEREVIEW_SEMGREP_MAX_MEMORY"]]
    for c in configs:
        cmd += ["--config", c]
    cmd.append(target)
    subprocess.run(cmd, check=False)
    return out_file if out_file.exists() else None


def run_bandit(target: str, out_file: Path) -> Optional[Path]:
    exe = shutil.which("bandit")
    if not exe:
        print("bandit not found: install it or pass --bandit-json with an existing file")
        return None
    # Bandit exits with code 1 when it finds issues, so do not use check=True
    subprocess.run([exe, "-r", target, "-f", "json", "-o", str(out_file), "-q"], check=False)
    return out_file if out_file.exists() else None


def run_all(cfg: Config, run_dir: Path) -> Tuple[Optional[Path], Optional[Path]]:
    sarif = Path(cfg.sarif_path) if cfg.sarif_path else run_semgrep(cfg.target, run_dir / "semgrep.sarif", cfg.semgrep_configs)
    bandit = Path(cfg.bandit_path) if cfg.bandit_path else run_bandit(cfg.target, run_dir / "bandit.json")
    return sarif, bandit
