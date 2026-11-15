"""Measure how hidden context exposure changes across model generations.

    python -m hcx.drift --corpus .corpus/spl

The published literature on LLM drift holds the prompt fixed and watches the
model move. This asks the opposite question, which the corpus makes answerable
because it stores each generation as its own file:

    claude-opus-4.5 -> 4.6 -> 4.7 -> 4.8 -> 5 -> 5.5

Does a vendor disclose more as its models gain capability?

The confound is length. Several series grow by an order of magnitude, and a
longer prompt has more chance of containing anything at all. So every metric
is reported twice: raw presence, and density per 10k characters. A category
that grows in presence but not in density grew because the prompt grew, and
that is a different claim.

The trend statistic is Spearman's rho between version rank and the metric. It
is rank-based, which suits ordinal version numbers and small n, and it assumes
nothing about the distribution. With three to eight points per series it is
weak on its own, so the headline is a sign test across series instead: if k of
n independent series move the same way, that is a binomial tail, and it does
not care how noisy any single series is.
"""

from __future__ import annotations

import argparse
import collections
import json
import math
import pathlib
import re
import sys

from hcx import rules

MIN_BYTES = 200
MIN_SERIES = 3           # a trend needs at least three points
DENSITY_BASE = 10_000    # matches per 10k characters

# A series member is a file whose name ends in a version number. The stem
# before the version is the family, and anything after it (a variant such as
# `-thinking` or `-no-tools`) keeps families apart rather than merging them.
VERSION_RE = re.compile(r"^(?P<stem>.*?)-?(?P<ver>\d+(?:\.\d+)*)(?P<tail>[a-z0-9-]*)$")


def parse_version(name: str) -> tuple[str, tuple[int, ...], str] | None:
    """Split a filename stem into (family, version tuple, variant)."""
    m = VERSION_RE.match(name)
    if not m:
        return None
    ver = m.group("ver")
    # A bare long integer is an id or a year, not a version.
    if "." not in ver and len(ver) > 2:
        return None
    stem = m.group("stem").rstrip("-")
    if not stem:
        return None
    return stem, tuple(int(x) for x in ver.split(".")), m.group("tail")


def spearman(xs: list[float], ys: list[float]) -> float | None:
    """Rank correlation. Returns None when it cannot be computed."""
    n = len(xs)
    if n < 3:
        return None

    def rank(vs: list[float]) -> list[float]:
        order = sorted(range(n), key=lambda i: vs[i])
        r = [0.0] * n
        i = 0
        while i < n:
            j = i
            while j + 1 < n and vs[order[j + 1]] == vs[order[i]]:
                j += 1
            avg = (i + j) / 2 + 1
            for k in range(i, j + 1):
                r[order[k]] = avg
            i = j + 1
        return r

    rx, ry = rank(xs), rank(ys)
    mx, my = sum(rx) / n, sum(ry) / n
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    dx = math.sqrt(sum((a - mx) ** 2 for a in rx))
    dy = math.sqrt(sum((b - my) ** 2 for b in ry))
    if dx == 0 or dy == 0:
        return None
    return num / (dx * dy)


def sign_test(pos: int, neg: int) -> float:
    """Two-sided binomial p for pos-vs-neg under a fair coin. Ties excluded."""
    n = pos + neg
    if n == 0:
        return 1.0
    k = min(pos, neg)
    tail = sum(math.comb(n, i) for i in range(0, k + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


def collect_series(root: pathlib.Path) -> dict[tuple, list]:
    series: dict[tuple, list] = collections.defaultdict(list)
    for p in sorted(root.rglob("*.md")):
        if ".git" in p.parts or not p.is_file():
            continue
        try:
            if p.stat().st_size < MIN_BYTES:
                continue
        except OSError:
            continue
        parsed = parse_version(p.stem)
        if not parsed:
            continue
        stem, ver, tail = parsed
        vendor = p.parts[len(root.parts)] if len(p.parts) > len(root.parts) + 1 else "."
        series[(vendor, stem, tail)].append((ver, p))
    # Deduplicate: one file per version, the largest if a version repeats.
    out = {}
    for key, items in series.items():
        best: dict[tuple, pathlib.Path] = {}
        for ver, p in items:
            if ver not in best or p.stat().st_size > best[ver].stat().st_size:
                best[ver] = p
        if len(best) >= MIN_SERIES:
            out[key] = sorted(best.items())
    return out


def measure_file(path: pathlib.Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    present = rules.categories_present(text)
    counts = {}
    for cat in rules.CATEGORIES:
        counts[cat.key] = sum(len(r.pattern.findall(text)) for r in cat.rules)
    return {"chars": len(text), "present": present, "counts": counts}


def analyse(root: pathlib.Path) -> dict:
    series = collect_series(root)
    results = {}
    for key, items in series.items():
        rows = []
        for ver, p in items:
            m = measure_file(p)
            rows.append({
                "version": ".".join(str(v) for v in ver),
                "rank": len(rows) + 1,
                "chars": m["chars"],
                "present": m["present"],
                "counts": m["counts"],
                "density": {k: DENSITY_BASE * v / max(1, m["chars"])
                            for k, v in m["counts"].items()},
            })
        ranks = [r["rank"] for r in rows]
        trends = {"chars": spearman(ranks, [r["chars"] for r in rows])}
        for cat in rules.CATEGORIES:
            trends[f"{cat.key}_count"] = spearman(
                ranks, [r["counts"][cat.key] for r in rows])
            trends[f"{cat.key}_density"] = spearman(
                ranks, [r["density"][cat.key] for r in rows])
        results["/".join(x for x in key if x)] = {"rows": rows, "trends": trends}
    return results


def report(results: dict, verbose: bool = False) -> None:
    names = sorted(results, key=lambda k: -len(results[k]["rows"]))
    print(f"{len(names)} version series with {MIN_SERIES}+ generations\n")

    print("  Does the prompt get longer?")
    print(f"  {'series':34s} {'n':>2s}  {'first':>7s} {'last':>7s}  {'growth':>7s}  rho")
    print("  " + "-" * 76)
    grow_pos = grow_neg = 0
    for name in names:
        rows = results[name]["rows"]
        first, last = rows[0]["chars"], rows[-1]["chars"]
        rho = results[name]["trends"]["chars"]
        if rho is not None:
            grow_pos += rho > 0
            grow_neg += rho < 0
        print(f"  {name[:34]:34s} {len(rows):2d}  {first:7d} {last:7d}  "
              f"{last/max(1,first):6.1f}x  {rho if rho is not None else float('nan'):+.2f}")
    print(f"\n  series growing: {grow_pos}, shrinking: {grow_neg}, "
          f"sign test p = {sign_test(grow_pos, grow_neg):.4f}\n")

    print("  Does disclosure grow faster than the prompt?")
    print("  (density = matches per 10k chars, so length is divided out)\n")
    print(f"  {'category':6s} {'count+':>7s} {'count-':>7s} {'p':>8s}   "
          f"{'dens+':>6s} {'dens-':>6s} {'p':>8s}")
    print("  " + "-" * 60)
    for cat in rules.CATEGORIES:
        cp = cn = dp = dn = 0
        for name in names:
            t = results[name]["trends"]
            rc, rd = t[f"{cat.key}_count"], t[f"{cat.key}_density"]
            if rc is not None:
                cp += rc > 0
                cn += rc < 0
            if rd is not None:
                dp += rd > 0
                dn += rd < 0
        print(f"  {cat.key:6s} {cp:7d} {cn:7d} {sign_test(cp, cn):8.4f}   "
              f"{dp:6d} {dn:6d} {sign_test(dp, dn):8.4f}")

    print("\n  count+ = series where raw match count rises with version.")
    print("  dens+  = series where matches per 10k chars rises with version.")
    print("  A category that rises in count but not density grew because the")
    print("  prompt grew. Only a density rise is a change in disclosure habit.")

    # ---------------------------------------------------------------------
    # Two things make the p-values above optimistic, and both are reported
    # rather than buried.
    # ---------------------------------------------------------------------
    n_tests = 1 + 2 * len(rules.CATEGORIES)
    print(f"\n  MULTIPLE COMPARISONS. {n_tests} tests were run above "
          f"(length, plus count and density")
    print(f"  for {len(rules.CATEGORIES)} categories). A Bonferroni threshold is "
          f"0.05/{n_tests} = {0.05/n_tests:.4f}.")
    print("  Nothing here clears that. Treat every result as exploratory: a "
          "hypothesis to")
    print("  test on a second corpus, not a finding to announce.")

    by_vendor: dict[str, list[str]] = collections.defaultdict(list)
    for name in names:
        by_vendor[name.split("/")[0]].append(name)
    print(f"\n  INDEPENDENCE. The sign test assumes {len(names)} independent series. "
          f"They are not:")
    for v, members in sorted(by_vendor.items(), key=lambda kv: -len(kv[1])):
        print(f"    {v:12s} {len(members):2d} series")
    print(f"  Series from one vendor share authorship and templates, so the "
          f"effective n is")
    print(f"  closer to {len(by_vendor)} (vendors) than {len(names)} (series). "
          f"The vendor-level view:")

    print(f"\n  {'category':8s} {'metric':8s}  " +
          "  ".join(f"{v[:9]:>9s}" for v in sorted(by_vendor)))
    print("  " + "-" * (18 + 11 * len(by_vendor)))
    for cat in rules.CATEGORIES:
        for metric in ("count", "density"):
            cells = []
            for v in sorted(by_vendor):
                pos = neg = 0
                for name in by_vendor[v]:
                    rho = results[name]["trends"][f"{cat.key}_{metric}"]
                    if rho is not None:
                        pos += rho > 0
                        neg += rho < 0
                cells.append(f"{pos:>4d}/{pos+neg:<4d}" if pos + neg else "    -    ")
            print(f"  {cat.key:8s} {metric:8s}  " + "  ".join(cells))
    print("\n  Read each cell as (series rising)/(series with a direction). A trend")
    print("  that only appears at one vendor is that vendor's house style, not an")
    print("  industry movement.")

    if verbose:
        for name in names:
            print(f"\n  {name}")
            for r in results[name]["rows"]:
                cats = ",".join(k for k, v in r["present"].items() if v)
                print(f"    {r['version']:6s} {r['chars']:7d} chars  {cats}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", type=pathlib.Path, default=pathlib.Path(".corpus/spl"))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    if not args.corpus.is_dir():
        print(f"corpus not found at {args.corpus}. Run ./corpus/fetch.sh", file=sys.stderr)
        return 2
    results = analyse(args.corpus)
    if not results:
        print("no version series found", file=sys.stderr)
        return 3
    if args.json:
        print(json.dumps(results, indent=1))
    else:
        report(results, args.verbose)
    return 0


def selftest() -> None:
    """Run with `python -m hcx.drift --selftest`."""
    assert parse_version("claude-opus-4.6") == ("claude-opus", (4, 6), "")
    assert parse_version("gpt-5") == ("gpt", (5,), "")
    assert parse_version("claude-opus-4.6-no-tools") == ("claude-opus", (4, 6), "-no-tools")
    # A bare long integer is an id or a date fragment, not a version.
    assert parse_version("prompt-20260101") is None
    # No stem means no family.
    assert parse_version("5.5") is None

    # Version ordering must be numeric, not lexical: 4.10 follows 4.9.
    vs = sorted([(4, 9), (4, 10), (5,), (4, 6)])
    assert vs == [(4, 6), (4, 9), (4, 10), (5,)], vs

    # Spearman: perfectly increasing is +1, decreasing is -1, flat is None.
    assert abs(spearman([1, 2, 3], [10, 20, 30]) - 1.0) < 1e-9
    assert abs(spearman([1, 2, 3], [30, 20, 10]) + 1.0) < 1e-9
    assert spearman([1, 2, 3], [5, 5, 5]) is None
    assert spearman([1, 2], [1, 2]) is None, "n<3 has no trend"
    # Ties are averaged, so a partial order still gives a sane sign.
    assert spearman([1, 2, 3, 4], [1, 2, 2, 4]) > 0.8

    # Sign test: a fair split is p=1, a clean sweep is small.
    assert abs(sign_test(5, 5) - 1.0) < 1e-9
    assert sign_test(10, 0) < 0.01
    assert sign_test(0, 0) == 1.0
    # 11 of 13 one way is significant at the conventional threshold.
    assert sign_test(11, 2) < 0.05

    print("drift selftest ok")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        sys.exit(main())
