"""Command line interface.

    python -m hcx.scan scan    PROMPT.md          one file, full evidence
    python -m hcx.scan census  DIR/               category rates over a tree
    python -m hcx.scan migrate REPORT.md          OWASP identifier linter

There is no network code in this package, by construction rather than by
policy. Every entry point takes a path on disk. A scanner that cannot reach a
live endpoint cannot be pointed at somebody else's product, by its author, by
an employer, or by anyone who clones it. Fetching the public corpus is a
separate shell script that this package never imports.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from hcx import rules, taxonomy

# Files below this size are stubs, redirects or front matter. Including them
# drags every rate toward zero without telling you anything about prompts.
MIN_BYTES = 200

# A rate computed over fewer than this many files is noise presented as a
# number. The census refuses to print one rather than print a bad one.
MIN_CENSUS_FILES = 30


def read_or_none(path: pathlib.Path) -> str | None:
    """`_read`, but None instead of an exception when the file will not open.

    A corpus walk must survive one bad file. `errors="replace"` handles bad
    bytes, but not a file the operating system refuses to open at all: a
    permission denial, a broken link, a path the filesystem reports and then
    cannot serve, or an antivirus filter holding the handle. One of those
    stopped a census 900 files into a 1,693-file corpus and printed nothing
    at all, which is worse than a rate with a hole in it, because a rate with
    a hole in it can be declared. So the walkers skip, count and print.
    """
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def cmd_scan(args: argparse.Namespace) -> int:
    path = pathlib.Path(args.path)
    if not path.is_file():
        print(f"not a file: {path}", file=sys.stderr)
        return 2
    text = read_or_none(path)
    if text is None:
        print(f"cannot be opened: {path}", file=sys.stderr)
        return 2
    findings = rules.scan_text(text)
    if args.json:
        print(json.dumps([f.__dict__ for f in findings], indent=1))
        return 0

    print(f"{path}")
    if not findings:
        print("  no findings")
        print("\n  Absence of findings is not evidence of safety. These detectors")
        print("  cover six categories with measured, imperfect precision; see")
        print("  RESEARCH.md for what they miss.")
        return 0

    # Count distinct disclosures, not rule hits. C1 alone has fourteen rules
    # and one line of a tool manifest can match three of them, so the raw
    # length of `findings` is a count of regexes rather than of problems.
    # Every match is still printed below as evidence.
    sites = {(f.category, f.line) for f in findings}
    by_cat = {f.category for f in findings}
    print(f"  {len(sites)} disclosures across {len(by_cat)} categories, "
          f"from {len(findings)} rule matches\n")
    shown = findings if args.all else findings[: args.limit]
    for f in shown:
        print(f.render())
        print()
    if len(shown) < len(findings):
        print(f"  ... {len(findings) - len(shown)} more; pass --all to see them")
    return 0


def _iter_files(root: pathlib.Path, pattern: str):
    for p in sorted(root.rglob(pattern)):
        if not p.is_file() or ".git" in p.parts:
            continue
        try:
            if p.stat().st_size < MIN_BYTES:
                continue
        except OSError:
            continue
        yield p


def _cred_gate(args: argparse.Namespace, counts: dict[str, int]) -> int:
    """Exit 4 unless the credential count is the one recorded on the command.

    Both output modes call this. The first version ran it only after the text
    table, so `--json --expect-cred 0` exited 0 on a corpus with a hit: a gate
    an unrelated flag walks past. Messages go to stderr so stdout stays
    parseable JSON.
    """
    if args.expect_cred is None:
        return 0
    got = counts.get("CRED", 0)
    if got != args.expect_cred:
        print(f"CRED is {got} file(s), expected {args.expect_cred}.", file=sys.stderr)
        print("Read the new hit by hand, then change the expected count "
              "deliberately.", file=sys.stderr)
        return 4
    print(f"CRED matches the recorded {args.expect_cred} for this corpus.",
          file=sys.stderr)
    return 0


def cmd_census(args: argparse.Namespace) -> int:
    root = pathlib.Path(args.path)
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2

    counts: dict[str, int] = {}
    per_group: dict[str, dict[str, int]] = {}
    unreadable: list[pathlib.Path] = []
    n = 0
    for p in _iter_files(root, args.glob):
        text = read_or_none(p)
        if text is None:
            unreadable.append(p)
            continue
        present = rules.categories_present(text)
        n += 1
        group = p.relative_to(root).parts[0] if len(p.relative_to(root).parts) > 1 else "."
        g = per_group.setdefault(group, {"_n": 0})
        g["_n"] += 1
        for key, hit in present.items():
            if hit:
                counts[key] = counts.get(key, 0) + 1
                g[key] = g.get(key, 0) + 1

    if n == 0:
        print(f"no files matching {args.glob!r} of at least {MIN_BYTES} bytes under {root}",
              file=sys.stderr)
        return 2

    if n < MIN_CENSUS_FILES and not args.force:
        print(f"refusing to report rates over {n} files.", file=sys.stderr)
        print(f"Below {MIN_CENSUS_FILES} a percentage is noise with a decimal point.",
              file=sys.stderr)
        print("Pass --force if you want the counts anyway.", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps({"files": n, "counts": counts, "groups": per_group,
                          "unreadable": [str(p) for p in unreadable]}, indent=1))
        return _cred_gate(args, counts)

    print(f"{n} files, at least {MIN_BYTES} bytes each, under {root}\n")
    order = [c.key for c in rules.CATEGORIES] + ["CRED"]
    labels = {c.key: c.owasp for c in rules.CATEGORIES}
    labels["CRED"] = "Credential or token in hidden context"
    for key in order:
        c = counts.get(key, 0)
        bar = "#" * round(40 * c / n)
        print(f"  {key:5s} {c:5d} / {n}  {100.0 * c / n:5.1f}%  {bar}")
        print(f"        {labels[key]}")
    print()
    if unreadable:
        # Named, not just counted. A denominator that quietly shrank is the
        # exact failure this repository is about.
        print(f"  {len(unreadable)} file(s) could not be opened and are NOT in "
              f"the {n} above:")
        for p in unreadable[:10]:
            print(f"    {p}")
        if len(unreadable) > 10:
            print(f"    ... and {len(unreadable) - 10} more")
        print()
    weak = ", ".join(c.key for c in rules.CATEGORIES if c.confidence == "low")
    print("  These are detector hit rates, not measured exposure. Precision is")
    print("  reported per category in RESEARCH.md and is not uniform.")
    print(f"  {weak} are weak signals and are known to over-report.")

    return _cred_gate(args, counts)


def cmd_migrate(args: argparse.Namespace) -> int:
    path = pathlib.Path(args.path)
    if not path.is_file():
        print(f"not a file: {path}", file=sys.stderr)
        return 2
    text = read_or_none(path)
    if text is None:
        print(f"cannot be opened: {path}", file=sys.stderr)
        return 2
    refs = list(taxonomy.find_references(text))
    interesting = [r for r in refs
                   if r.verdict in (taxonomy.AMBIGUOUS, taxonomy.STALE, taxonomy.PROVISIONAL)]

    if args.write:
        # This rewrites identifiers wherever they appear, and it cannot tell an
        # ID used as a label ("mapped to LLM06:2025") from one mentioned in a
        # sentence about the taxonomy ("LLM07:2025 became LLM08:2026"). On
        # prose it will produce nonsense. Findings exports and report tables
        # are the intended input. Review the diff either way.
        print("note: --write cannot distinguish a classification from a mention.",
              file=sys.stderr)
        print("      Intended for findings exports, not prose. Review the diff.",
              file=sys.stderr)
        new_text, _ = taxonomy.migrate(text)
        if new_text != text:
            # newline="" or Python expands every "\n" to os.linesep on write,
            # which turns a two-identifier edit into a diff touching every
            # line of the file on Windows, and fights `* text=auto eol=lf`
            # in this repository's own .gitattributes.
            path.write_text(new_text, encoding="utf-8", newline="")
            # Count the stale ones, not every reference in the file. The old
            # form subtracted the stale leftovers from the total and reported
            # "rewrote 6" for a file with four current IDs and two stale ones.
            rewritten = sum(1 for r in refs if r.verdict == taxonomy.STALE)
            print(f"{path}: rewrote {rewritten} stale identifier(s)")
        else:
            print(f"{path}: nothing to rewrite")
        # Re-read from disk rather than trusting new_text, so what is
        # reported is what actually landed in the file.
        written = read_or_none(path)
        if written is None:
            print(f"wrote {path} but cannot read it back", file=sys.stderr)
            return 2
        remaining = [r for r in taxonomy.find_references(written)
                     if r.verdict == taxonomy.AMBIGUOUS]
        if remaining:
            print(f"{len(remaining)} ambiguous reference(s) left alone: the edition "
                  "cannot be inferred, so you must choose.")
            for r in remaining:
                print(f"  line {r.line}: {r.raw}  ->  {r.suggestion}")
        return 1 if remaining else 0

    print(f"{path}: {len(refs)} OWASP reference(s), {len(interesting)} need attention\n")
    for r in interesting:
        print(f"  line {r.line}: {r.raw}  [{r.verdict}]")
        print(f"    {r.detail}")
        if r.suggestion:
            print(f"    suggest: {r.suggestion}")
        print()
    if not interesting:
        print("  every reference is current and unambiguous")
    ambiguous = sum(1 for r in interesting if r.verdict == taxonomy.AMBIGUOUS)
    return 1 if ambiguous else 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="hcx", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="score one file against LLM08:2026")
    s.add_argument("path")
    s.add_argument("--json", action="store_true")
    s.add_argument("--all", action="store_true", help="show every finding")
    s.add_argument("--limit", type=int, default=12)
    s.set_defaults(func=cmd_scan)

    c = sub.add_parser("census", help="category rates over a tree of prompts")
    c.add_argument("path")
    c.add_argument("--glob", default="*.md")
    c.add_argument("--json", action="store_true")
    c.add_argument("--force", action="store_true",
                   help="report rates even below the minimum sample size")
    # The published credential claim covers four corpora. It was once
    # measured on one of them and generalised to the rest, which is the worst
    # mistake this repository has made. CI now asserts the count per corpus,
    # so the claim cannot drift without a human changing a number on purpose.
    c.add_argument("--expect-cred", type=int, default=None, metavar="N",
                   help="exit 4 unless exactly N files carry a credential")
    c.set_defaults(func=cmd_census)

    m = sub.add_parser("migrate", help="find stale and ambiguous OWASP identifiers")
    m.add_argument("path")
    m.add_argument("--write", action="store_true",
                   help="rewrite the resolvable ones in place")
    m.set_defaults(func=cmd_migrate)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
