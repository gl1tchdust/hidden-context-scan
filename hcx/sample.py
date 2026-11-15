"""Draw a reproducible stratified sample for hand-labelling.

    python -m hcx.sample --corpus .corpus/spl --n 50 --seed 20261115

Proportional by vendor, because precision is reported against the whole
corpus and a sample that over-weights small vendors would not describe it.
Vendors with at least `--floor` files get at least one slot anyway, so a
category that only appears at one vendor is not invisible.

The seed and the corpus pin together make the draw reproducible: anyone can
regenerate the exact file list and check the labels against it.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import random
import sys

MIN_BYTES = 200


def vendor_of(path: pathlib.Path, root: pathlib.Path) -> str:
    rel = path.relative_to(root).parts
    return rel[0] if len(rel) > 1 else "."


def collect(root: pathlib.Path, max_bytes: int) -> dict[str, list[pathlib.Path]]:
    by_vendor: dict[str, list[pathlib.Path]] = collections.defaultdict(list)
    for p in sorted(root.rglob("*.md")):
        if not p.is_file() or ".git" in p.parts:
            continue
        size = p.stat().st_size
        if size < MIN_BYTES or size > max_bytes:
            continue
        by_vendor[vendor_of(p, root)].append(p)
    return by_vendor


def allocate(by_vendor: dict[str, list], n: int, floor: int) -> dict[str, int]:
    """Largest-remainder apportionment, with a floor for sizeable vendors."""
    total = sum(len(v) for v in by_vendor.values())
    exact = {k: n * len(v) / total for k, v in by_vendor.items()}
    quota = {k: int(x) for k, x in exact.items()}
    # Guarantee a slot to any vendor big enough to matter.
    for k, files in by_vendor.items():
        if len(files) >= floor:
            quota[k] = max(quota[k], 1)
    # Hand out what is left by largest fractional remainder.
    while sum(quota.values()) < n:
        k = max(by_vendor, key=lambda k: (exact[k] - quota[k], len(by_vendor[k])))
        quota[k] += 1
    # And take back from the largest if the floor overshot.
    while sum(quota.values()) > n:
        k = max((k for k in quota if quota[k] > 1), key=lambda k: quota[k])
        quota[k] -= 1
    return quota


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", type=pathlib.Path, default=pathlib.Path(".corpus/spl"))
    ap.add_argument("--n", type=int, default=50)
    ap.add_argument("--seed", type=int, default=20261115)
    ap.add_argument("--floor", type=int, default=10,
                    help="vendors with at least this many files get a slot")
    ap.add_argument("--max-bytes", type=int, default=20000,
                    help="skip files larger than this; see the bias note")
    ap.add_argument("--exclude", action="append", default=[],
                    help="a path already labelled, so the draw tops up rather "
                         "than starting over")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if not args.corpus.is_dir():
        print(f"corpus not found at {args.corpus}. Run ./corpus/fetch.sh", file=sys.stderr)
        return 2

    by_vendor = collect(args.corpus, args.max_bytes)
    excluded = set(args.exclude)
    for k in list(by_vendor):
        by_vendor[k] = [p for p in by_vendor[k]
                        if str(p.relative_to(args.corpus)).replace("\\", "/") not in excluded]
        if not by_vendor[k]:
            del by_vendor[k]

    quota = allocate(by_vendor, args.n, args.floor)
    rng = random.Random(args.seed)
    picked: list[str] = []
    for vendor in sorted(by_vendor):
        files = sorted(by_vendor[vendor])
        k = min(quota.get(vendor, 0), len(files))
        for p in rng.sample(files, k):
            picked.append(str(p.relative_to(args.corpus)).replace("\\", "/"))
    picked.sort()

    if args.json:
        print(json.dumps({"seed": args.seed, "n": len(picked),
                          "max_bytes": args.max_bytes, "files": picked}, indent=1))
        return 0

    pool = sum(len(v) for v in by_vendor.values())
    print(f"pool {pool} files between {MIN_BYTES} and {args.max_bytes} bytes, "
          f"seed {args.seed}")
    for vendor in sorted(quota, key=lambda k: -len(by_vendor.get(k, []))):
        if quota[vendor]:
            print(f"  {vendor:12s} {len(by_vendor[vendor]):4d} available -> "
                  f"{quota[vendor]:2d} drawn")
    print()
    for p in picked:
        print(p)
    return 0


def selftest() -> None:
    fake = {"a": list(range(60)), "b": list(range(30)), "c": list(range(10)),
            "d": list(range(2))}
    q = allocate(fake, 20, floor=10)
    assert sum(q.values()) == 20, q
    assert q["a"] > q["b"] > q["c"], q
    assert q["c"] >= 1, "a vendor at the floor must get a slot"
    # A tiny vendor below the floor gets nothing rather than distorting rates.
    assert q.get("d", 0) == 0, q
    # Asking for more than the floors require must still total exactly n.
    assert sum(allocate(fake, 4, floor=10).values()) == 4
    print("sample selftest ok")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        sys.exit(main())
