"""Split the benchmark answer key into a development half and a test half, once, with a fixed seed.

Tune and debug on dev only. Report final results on test only. The split is stratified: each category
(sqli, cmdi, xxe, ...) and each answer (real / not real) is divided evenly, so both halves look alike.
Usage: python scripts/make_split.py data/benchmark-python/expectedresults-0.1.csv
Writes data/splits/dev.csv and data/splits/test.csv in the same format, so they work with --only-scored and evaluate.
"""
import random
import sys
from collections import defaultdict
from pathlib import Path

SEED = 42
src = Path(sys.argv[1])
header, rows = [], []
for line in src.read_text().splitlines():
    (header if line.startswith("#") else rows).append(line)
strata = defaultdict(list)
for r in rows:
    if r.strip():
        cols = r.split(",")
        strata[(cols[1].strip(), cols[2].strip())].append(r)
dev, test = [], []
rng = random.Random(SEED)
for key in sorted(strata):
    group = sorted(strata[key])
    rng.shuffle(group)
    half = (len(group) + rng.randint(0, 1)) // 2      # odd-sized groups: a coin flip decides which half gets the extra
    dev += group[:half]
    test += group[half:]
out = Path(__file__).resolve().parent.parent / "data" / "splits"
out.mkdir(parents=True, exist_ok=True)
for name, part in (("dev", dev), ("test", test)):
    (out / f"{name}.csv").write_text("\n".join(header + sorted(part)) + "\n")
    print(f"{name}: {len(part)} test cases -> {out / (name + '.csv')}")