"""Generate the README figure from the corpora, so it cannot drift.

    python docs/make_figure.py

Writes docs/corpus-spread-light.svg and docs/corpus-spread-dark.svg.

Every number in the figure is computed here from the pinned corpora by the same
`hcx.rules.categories_present` the census uses. Nothing is typed in. CI
regenerates both files and fails if either differs from the committed copy,
because a hand-maintained figure is the same defect as a hand-maintained table
and this repository has already shipped that defect twice.

Palette: the validated categorical slots 1 to 4 from the data-viz reference
instance, which pass the lightness band, chroma floor, adjacent-pair CVD
separation and normal-vision floor in both modes. Light-mode aqua and yellow
fall below 3:1 against the light surface, so the relief rule applies: the C1
group carries visible value labels and the README keeps the full table.
"""

from __future__ import annotations

import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from hcx import rules  # noqa: E402
from hcx.scan import MIN_BYTES, is_corpus_file, read_or_none  # noqa: E402

# (label, path, glob, legend note). Order is fixed and the hue follows the
# corpus, never its rank, so adding a corpus never repaints the others.
CORPORA = [
    ("A", ".corpus/spl", "*.md", "frontier vendors"),
    ("B1", ".corpus/bigprompt/CustomInstructions", "*.md", "custom GPT authors"),
    ("B2", ".corpus/bigprompt/SystemPrompts", "*.md", "vendor, 2nd curator"),
    ("C", ".corpus/aitools", "*.txt", "coding agents"),
]

THEMES = {
    "light": {
        "surface": "#fcfcfb", "primary": "#0b0b0b", "secondary": "#52514e",
        "grid": "#e3e2de",
        "series": ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"],
    },
    "dark": {
        "surface": "#1a1a19", "primary": "#f0efec", "secondary": "#c3c2b7",
        "grid": "#333230",
        "series": ["#3987e5", "#d95926", "#199e70", "#c98500"],
    },
}

# An axis label for every category. Checked against rules.CATEGORIES at render
# time so adding a seventh detector fails here instead of producing a chart
# with a blank column.
SHORT_LABELS = {
    "C1": "tool and function", "C2": "control logic",
    "C3": "refusal and safety", "C4": "permissions",
    "C5": "output structure", "C6": "capability",
}

W, H = 920, 452
M_LEFT, M_RIGHT, M_TOP, M_BOT = 52, 18, 104, 96
Y_MAX = 80
FONT = ("system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, "
        "sans-serif")


def measure() -> tuple[dict[str, dict[str, float]], dict[str, int]]:
    """Category hit rates per corpus, and the file count per corpus."""
    rates: dict[str, dict[str, float]] = {}
    counts: dict[str, int] = {}
    for label, root, glob, _note in CORPORA:
        base = pathlib.Path(root)
        if not base.is_dir():
            raise SystemExit(
                f"corpus not found at {base}.\n"
                "Run ./corpus/fetch.sh and ./corpus/fetch-comparison.sh first."
            )
        hits = {c.key: 0 for c in rules.CATEGORIES}
        n = 0
        unreadable: list[str] = []
        for p in sorted(base.rglob(glob)):
            if not is_corpus_file(p):
                continue
            try:
                if p.stat().st_size < MIN_BYTES:
                    continue
            except OSError:
                continue
            text = read_or_none(p)
            if text is None:
                # The census skips these and says so. A figure cannot: a file
                # that opens on one machine and not another changes n, shifts
                # every rate, and makes CI's byte-comparison fail with a
                # message about drift when the real cause is a locked file.
                unreadable.append(str(p))
                continue
            n += 1
            present = rules.categories_present(text)
            for key in hits:
                if present[key]:
                    hits[key] += 1
        if unreadable:
            raise SystemExit(
                f"{len(unreadable)} file(s) under {base} could not be opened, "
                "so this figure would not be reproducible:\n  "
                + "\n  ".join(unreadable[:10])
            )
        if n == 0:
            raise SystemExit(f"no files matched {glob!r} under {base}")
        counts[label] = n
        rates[label] = {k: 100.0 * v / n for k, v in hits.items()}
    return rates, counts


def _top_rounded(x: float, y: float, w: float, h: float, r: float) -> str:
    """A bar anchored to the baseline with its data end rounded."""
    r = min(r, w / 2, h) if h > 0 else 0
    if h <= 0:
        return ""
    return (f"M{x:.2f},{y + h:.2f}V{y + r:.2f}"
            f"A{r:.2f},{r:.2f} 0 0 1 {x + r:.2f},{y:.2f}"
            f"H{x + w - r:.2f}"
            f"A{r:.2f},{r:.2f} 0 0 1 {x + w:.2f},{y + r:.2f}"
            f"V{y + h:.2f}Z")


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render(rates, counts, theme_name: str) -> str:
    t = THEMES[theme_name]
    cats = [c.key for c in rules.CATEGORIES]
    missing = [c for c in cats if c not in SHORT_LABELS]
    assert not missing, f"no axis label for {missing}; add it to SHORT_LABELS"
    assert len(CORPORA) <= len(t["series"]), "more corpora than validated hues"
    plot_w = W - M_LEFT - M_RIGHT
    plot_h = H - M_TOP - M_BOT
    base_y = M_TOP + plot_h
    group_w = plot_w / len(cats)
    bar_w, bar_gap = 25.0, 2.0
    band = len(CORPORA) * bar_w + (len(CORPORA) - 1) * bar_gap
    pad = (group_w - band) / 2

    o: list[str] = []
    a = o.append
    a(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
      f'viewBox="0 0 {W} {H}" role="img" '
      f'aria-label="Detector hit rates for six hidden context categories '
      f'across four corpora">')
    a(f'<rect width="{W}" height="{H}" fill="{t["surface"]}"/>')
    a(f'<g font-family="{FONT}">')

    # Title and subtitle.
    a(f'<text x="{M_LEFT}" y="34" font-size="19" font-weight="600" '
      f'fill="{t["primary"]}">The same six detectors, four separate corpora</text>')
    a(f'<text x="{M_LEFT}" y="56" font-size="13" fill="{t["secondary"]}">'
      f'Share of files where the category fires. OWASP LLM08:2026.</text>')

    # Legend. Always present at four series, and it carries each n.
    lx = M_LEFT
    for i, (label, _r, _g, note) in enumerate(CORPORA):
        a(f'<rect x="{lx}" y="70" width="10" height="10" rx="2" '
          f'fill="{t["series"][i]}"/>')
        txt = f"{label}  {note}, n={counts[label]:,}"
        a(f'<text x="{lx + 15}" y="79" font-size="12" '
          f'fill="{t["secondary"]}">{esc(txt)}</text>')
        # 6.3px per character is a measured-enough average for this stack at
        # 12px. The whole row is asserted to fit inside the canvas below,
        # because a legend that overflows is the one layout bug a palette
        # validator cannot catch.
        lx += 15 + 6.3 * len(txt) + 14
    assert lx < W - M_RIGHT, f"legend row overflows: ends at {lx:.0f} of {W}"

    # Recessive grid and y axis.
    for v in range(0, Y_MAX + 1, 20):
        y = base_y - plot_h * v / Y_MAX
        a(f'<line x1="{M_LEFT}" y1="{y:.2f}" x2="{W - M_RIGHT}" y2="{y:.2f}" '
          f'stroke="{t["grid"]}" stroke-width="1"/>')
        a(f'<text x="{M_LEFT - 10}" y="{y + 4:.2f}" font-size="11" '
          f'text-anchor="end" fill="{t["secondary"]}">{v}%</text>')

    # Bars.
    for gi, cat in enumerate(cats):
        gx = M_LEFT + gi * group_w
        for si, (label, _r, _g, _n) in enumerate(CORPORA):
            v = rates[label][cat]
            h = plot_h * v / Y_MAX
            x = gx + pad + si * (bar_w + bar_gap)
            a(f'<path d="{_top_rounded(x, base_y - h, bar_w, h, 4)}" '
              f'fill="{t["series"][si]}"/>')
            # Selective direct labels: the C1 group only. It carries the
            # headline spread and satisfies the light-mode relief rule
            # without putting a number on all twenty-four bars.
            if cat == "C1":
                a(f'<text x="{x + bar_w / 2:.2f}" y="{base_y - h - 7:.2f}" '
                  f'font-size="11" font-weight="600" text-anchor="middle" '
                  f'fill="{t["primary"]}">{v:.1f}</text>')
        short = SHORT_LABELS[cat]
        a(f'<text x="{gx + group_w / 2:.2f}" y="{base_y + 20}" font-size="13" '
          f'font-weight="600" text-anchor="middle" fill="{t["primary"]}">'
          f'{cat}</text>')
        a(f'<text x="{gx + group_w / 2:.2f}" y="{base_y + 35}" font-size="10.5" '
          f'text-anchor="middle" fill="{t["secondary"]}">{esc(short)}</text>')

    a(f'<line x1="{M_LEFT}" y1="{base_y}" x2="{W - M_RIGHT}" y2="{base_y}" '
      f'stroke="{t["grid"]}" stroke-width="1"/>')

    lo = min(rates[c[0]]["C1"] for c in CORPORA)
    hi = max(rates[c[0]]["C1"] for c in CORPORA)
    a(f'<text x="{M_LEFT}" y="{H - 26}" font-size="12" fill="{t["primary"]}">'
      f'C1 runs {lo:.1f}% to {hi:.1f}% on the same detector. The population '
      f'decides the rate.</text>')
    a(f'<text x="{M_LEFT}" y="{H - 10}" font-size="11" fill="{t["secondary"]}">'
      f'Detector hit rates, not measured exposure. Precision is per category '
      f'and is not uniform; see RESEARCH.md.</text>')
    a('</g></svg>')
    return "\n".join(o) + "\n"


def main() -> int:
    rates, counts = measure()
    for name in THEMES:
        out = HERE / f"corpus-spread-{name}.svg"
        out.write_text(render(rates, counts, name), encoding="utf-8",
                       newline="")
        print(f"wrote {out.relative_to(HERE.parent)}")
    print("\nC1 by corpus: " + "  ".join(
        f"{label} {rates[label]['C1']:.1f}%" for label, *_ in CORPORA))
    return 0


if __name__ == "__main__":
    sys.exit(main())
