#!/usr/bin/env bash
# Downloads the two things the evaluation needs into data/ (not committed to git, see .gitignore):
#   1. OWASP Benchmark for Python: 1,230 test files and the answer key (expectedresults-0.1.csv)
#   2. Semgrep community rules: the Python rules, used offline so every run is reproducible
# Both are pinned to a fixed commit, so you (and your examiner) always test against exactly the same files.
# Run from the project folder:  bash scripts/get_data.sh
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p data

BENCH_COMMIT=f1291485808b66e20ddb6b01b10dc71b3df8c8ba
RULES_COMMIT=9bbf021d0acffa3095fcffd17b2bc7787eb4796d

fetch () {  # fetch <url> <folder> <commit>
  if [ ! -d "data/$2" ]; then
    git clone --filter=blob:none "$1" "data/$2"
  fi
  git -C "data/$2" fetch --quiet origin "$3" || true
  git -C "data/$2" checkout --quiet "$3"
  echo "data/$2 is at $(git -C "data/$2" rev-parse --short HEAD)"
}

fetch https://github.com/OWASP-Benchmark/BenchmarkPython.git benchmark-python "$BENCH_COMMIT"
fetch https://github.com/semgrep/semgrep-rules.git semgrep-rules "$RULES_COMMIT"
echo "Done. Test code: data/benchmark-python/testcode   Answer key: data/benchmark-python/expectedresults-0.1.csv"
