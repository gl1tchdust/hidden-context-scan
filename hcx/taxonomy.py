"""OWASP identifier tables, and the migration that breaks reports.

OWASP renumbered eight of ten LLM risks between the 2025 and 2026 editions.
Only LLM01 and LLM02 kept both their number and their meaning. A bare `LLM08`
written against the 2025 list is still a valid 2026 identifier, so nothing
errors and nothing warns: the reference simply points at a different risk.

That is the failure this module exists to catch. It distinguishes three cases,
because they are not equally bad:

    AMBIGUOUS  a bare ID that means different things in 2025 and 2026.
               This is the dangerous one. A reader assumes the current edition.
    STALE      an ID correctly suffixed `:2025` whose risk moved in 2026.
               Not wrong, just dated, and invisible to a 2026 reader searching
               by the new number.
    STABLE     same number, same meaning in both editions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator

# ---------------------------------------------------------------------------
# OWASP Top 10 for LLM Applications
# 2025 edition, and 2026 edition published 2026-08-04.
# ---------------------------------------------------------------------------

LLM_2025 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

LLM_2026 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Excessive Agency",
    "LLM04": "Supply Chain",
    "LLM05": "Data and Model Poisoning",
    "LLM06": "Unbounded Consumption",
    "LLM07": "Misinformation",
    "LLM08": "Hidden Context Exposure",
    "LLM09": "Vector and Embedding Weaknesses",
    "LLM10": "Improper Output Handling",
}

# Where each 2025 identifier's risk went in 2026.
# LLM07 is the one that was re-scoped rather than renamed: System Prompt
# Leakage widened into Hidden Context Exposure, which now also covers tool
# schemas, control logic, refusal rules, permissions and output contracts.
MOVED_2025_TO_2026 = {
    "LLM01": "LLM01",
    "LLM02": "LLM02",
    "LLM03": "LLM04",
    "LLM04": "LLM05",
    "LLM05": "LLM10",
    "LLM06": "LLM03",
    "LLM07": "LLM08",
    "LLM08": "LLM09",
    "LLM09": "LLM07",
    "LLM10": "LLM06",
}

RESCOPED = {"LLM07": "widened from System Prompt Leakage into Hidden Context Exposure"}

# OWASP Top 10 for Agentic Applications, announced 2025-12-09. No prior
# edition exists, so these identifiers cannot collide across years yet.
ASI_2026 = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution (RCE)",
    "ASI06": "Memory and Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

# OWASP MCP Top 10. Beta, Phase 3 pilot testing, so these may still move.
# Carried here so a report that cites them can be told they are provisional.
MCP_2025 = {
    "MCP01": "Token Mismanagement & Secret Exposure",
    "MCP02": "Privilege Escalation via Scope Creep",
    "MCP03": "Tool Poisoning",
    "MCP04": "Software Supply Chain Attacks & Dependency Tampering",
    "MCP05": "Command Injection & Execution",
    "MCP06": "Prompt Injection via Contextual Payloads",
    "MCP07": "Insufficient Authentication & Authorization",
    "MCP08": "Lack of Audit and Telemetry",
    "MCP09": "Shadow MCP Servers",
    "MCP10": "Context Injection & Over-Sharing",
}

AMBIGUOUS = "ambiguous"
STALE = "stale"
STABLE = "stable"
PROVISIONAL = "provisional"

# `LLM08`, `LLM08:2026`, `LLM08:2025 Vector and Embedding Weaknesses`.
# The year group is optional, which is the whole point.
ID_RE = re.compile(r"\b(?P<fam>LLM|ASI|MCP)(?P<num>\d{2})(?::(?P<year>\d{4}))?\b")


@dataclass(frozen=True)
class Reference:
    """One OWASP identifier found in a document."""

    family: str
    number: str
    year: str | None
    line: int
    col: int
    raw: str
    verdict: str
    detail: str
    suggestion: str | None = None

    @property
    def ident(self) -> str:
        return f"{self.family}{self.number}"


def classify(family: str, number: str, year: str | None) -> tuple[str, str, str | None]:
    """Return (verdict, detail, suggested replacement) for one identifier."""
    ident = f"{family}{number}"

    if family == "ASI":
        if ident not in ASI_2026:
            return STABLE, f"{ident} is not a known ASI identifier", None
        return STABLE, f"{ident} {ASI_2026[ident]}; single edition, no collision", None

    if family == "MCP":
        if ident not in MCP_2025:
            return STABLE, f"{ident} is not a known MCP identifier", None
        return (PROVISIONAL,
                f"{ident} {MCP_2025[ident]}; OWASP MCP Top 10 is in beta and may renumber",
                None)

    if ident not in LLM_2025:
        return STABLE, f"{ident} is not a known LLM identifier", None

    moved_to = MOVED_2025_TO_2026[ident]
    stable = moved_to == ident

    if year == "2026":
        return STABLE, f"{ident}:2026 {LLM_2026[ident]}; current and explicit", None

    if year == "2025":
        if stable:
            return STABLE, f"{ident}:2025 {LLM_2025[ident]}; unchanged in 2026", None
        note = f"{ident}:2025 {LLM_2025[ident]} is {moved_to} in the 2026 edition"
        if ident in RESCOPED:
            note += f", and was {RESCOPED[ident]}"
        return STALE, note, f"{moved_to}:2026"

    # No year suffix. This is where reports go wrong.
    if stable:
        return STABLE, f"{ident} means {LLM_2026[ident]} in both editions", None
    note = (f"bare {ident} is {LLM_2025[ident]} in 2025 and "
            f"{LLM_2026[ident]} in 2026")
    return AMBIGUOUS, note, f"{ident}:2025 or {moved_to}:2026"


def find_references(text: str) -> Iterator[Reference]:
    """Yield every OWASP identifier in `text`, classified."""
    for lineno, line in enumerate(text.splitlines(), start=1):
        for m in ID_RE.finditer(line):
            fam, num, year = m.group("fam"), m.group("num"), m.group("year")
            verdict, detail, suggestion = classify(fam, num, year)
            yield Reference(
                family=fam, number=num, year=year,
                line=lineno, col=m.start() + 1, raw=m.group(0),
                verdict=verdict, detail=detail, suggestion=suggestion,
            )


def migrate(text: str) -> tuple[str, list[Reference]]:
    """Rewrite bare and stale LLM identifiers to explicit 2026 ones.

    Only identifiers this module can resolve unambiguously are rewritten.
    Anything provisional or unknown is reported and left alone, because a
    migration that guesses is worse than one that abstains.
    """
    refs = [r for r in find_references(text) if r.suggestion and "or" not in r.suggestion]
    out_lines = text.splitlines(keepends=True)
    # Rewrite right to left on each line so earlier column offsets stay valid.
    by_line: dict[int, list[Reference]] = {}
    for r in refs:
        by_line.setdefault(r.line, []).append(r)
    for lineno, line_refs in by_line.items():
        line = out_lines[lineno - 1]
        for r in sorted(line_refs, key=lambda x: -x.col):
            start = r.col - 1
            line = line[:start] + r.suggestion + line[start + len(r.raw):]
        out_lines[lineno - 1] = line
    return "".join(out_lines), list(find_references("".join(out_lines)))


def selftest() -> None:
    """Run with `python -m hcx.taxonomy`."""
    v, d, s = classify("LLM", "08", None)
    assert v == AMBIGUOUS and s == "LLM08:2025 or LLM09:2026", (v, s)

    v, d, s = classify("LLM", "06", "2025")
    assert v == STALE and s == "LLM03:2026", (v, s)
    assert "Excessive Agency" in d

    v, _, s = classify("LLM", "02", None)
    assert v == STABLE and s is None

    v, _, _ = classify("LLM", "01", "2026")
    assert v == STABLE

    v, d, _ = classify("MCP", "03", None)
    assert v == PROVISIONAL and "beta" in d

    v, _, _ = classify("ASI", "07", None)
    assert v == STABLE

    # LLM07:2025 is the re-scoped one and the detail must say so.
    _, d, _ = classify("LLM", "07", "2025")
    assert "widened" in d, d

    refs = list(find_references("see LLM06:2025 Excessive Agency and bare LLM08 here"))
    assert [r.verdict for r in refs] == [STALE, AMBIGUOUS], refs

    out, after = migrate("tagged LLM06:2025 Excessive Agency")
    assert out == "tagged LLM03:2026 Excessive Agency", out
    assert all(r.verdict == STABLE for r in after), after

    # A bare ambiguous ID must NOT be rewritten: we cannot know the edition.
    out, _ = migrate("tagged LLM08 here")
    assert out == "tagged LLM08 here", out

    # Every 2025 identifier must map somewhere real, and the map must be a
    # permutation: no two risks may land on the same 2026 number.
    assert set(MOVED_2025_TO_2026) == set(LLM_2025)
    assert sorted(MOVED_2025_TO_2026.values()) == sorted(LLM_2026)
    for old, new in MOVED_2025_TO_2026.items():
        assert LLM_2025[old] == LLM_2026[new] or old in RESCOPED, (old, new)

    print("taxonomy selftest ok")


if __name__ == "__main__":
    selftest()
