"""Check that no secret from .env has leaked into run output, tracked files or git history.

Reads every value in .env whose name ends in KEY, TOKEN, SECRET or PASSWORD, then searches for the
whole value and a 12-character piece of it. Secrets are never printed, only where they were found.
Usage: python scripts/check_secrets.py
"""
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SECRET_NAMES = ("KEY", "TOKEN", "SECRET", "PASSWORD")


def secrets() -> dict:
    found = {}
    for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            name, value = (s.strip().strip('"\'') for s in line.split("=", 1))
            if name.upper().endswith(SECRET_NAMES) and len(value) >= 16:
                found[name] = value
    return found


def needles(value: str) -> list:
    mid = len(value) // 2
    return [value, value[mid - 6: mid + 6]]   # the middle piece catches a key that was cut or wrapped


def git(*args) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True,
                          encoding="utf-8", errors="replace").stdout


checks = {
    ".env is listed in .gitignore": ".env" in (ROOT / ".gitignore").read_text(encoding="utf-8").split(),
    ".env is not tracked by git": git("ls-files", ".env").strip() == "",
    ".env never appeared in git history": git("log", "--all", "--oneline", "--", ".env").strip() == "",
}
leaks = []
keys = secrets()
places = {"runs/ folder (database, raw logs, reports)": [p for p in (ROOT / "runs").rglob("*") if p.is_file()]}
for p in ROOT.rglob("results-*.txt"):
    places.setdefault("result text files", []).append(p)
history = git("log", "--all", "-p")                     # every version of every committed file
tracked = [ROOT / f for f in git("ls-files").splitlines()]
for name, value in keys.items():
    for where, files in places.items():
        for p in files:
            data = p.read_bytes().decode("utf-8", errors="replace")
            if any(n in data for n in needles(value)):
                leaks.append(f"{name} found in {p.relative_to(ROOT)}")
    for p in tracked:
        if p.is_file() and any(n in p.read_bytes().decode("utf-8", errors="replace") for n in needles(value)):
            leaks.append(f"{name} found in tracked file {p.relative_to(ROOT)}")
    if any(n in history for n in needles(value)):
        leaks.append(f"{name} found in git history")

print(f"Secrets checked from .env: {len(keys)} ({', '.join(keys) or 'none'})")
scanned = sum(len(v) for v in places.values())
print(f"Files scanned: {scanned} output files, {len(tracked)} tracked files, plus full git history")
for label, ok in checks.items():
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
print(f"  {'PASS' if not leaks else 'FAIL'}  no secret found in output, tracked files or history")
for leak in leaks:
    print(f"        {leak}")