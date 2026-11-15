"""Tests for the OWASP identifier tables and the migration."""

import pytest

from hcx import taxonomy as tx


def test_module_selftest():
    tx.selftest()


def test_tables_are_complete_and_consistent():
    for table in (tx.LLM_2025, tx.LLM_2026, tx.ASI_2026, tx.MCP_2025):
        assert len(table) == 10
        assert all(v.strip() for v in table.values())
    # The migration must be a bijection: every 2026 slot filled exactly once.
    assert sorted(tx.MOVED_2025_TO_2026.values()) == sorted(tx.LLM_2026)


def test_only_llm01_and_llm02_are_stable():
    stable = {old for old, new in tx.MOVED_2025_TO_2026.items() if old == new}
    assert stable == {"LLM01", "LLM02"}


@pytest.mark.parametrize("ident,year,verdict", [
    ("LLM01", None, tx.STABLE),
    ("LLM02", None, tx.STABLE),
    ("LLM03", None, tx.AMBIGUOUS),
    ("LLM08", None, tx.AMBIGUOUS),
    ("LLM06", "2025", tx.STALE),
    ("LLM03", "2026", tx.STABLE),
    ("ASI02", None, tx.STABLE),
    ("MCP03", None, tx.PROVISIONAL),
])
def test_classify(ident, year, verdict):
    fam, num = ident[:3], ident[3:]
    got, _, _ = tx.classify(fam, num, year)
    assert got == verdict


def test_every_moved_bare_id_is_ambiguous():
    """Any 2025 ID whose risk moved must be flagged when written bare."""
    for old, new in tx.MOVED_2025_TO_2026.items():
        verdict, _, _ = tx.classify("LLM", old[3:], None)
        assert verdict == (tx.STABLE if old == new else tx.AMBIGUOUS), old


def test_migrate_rewrites_stale_and_leaves_ambiguous():
    text = "LLM06:2025 moved, LLM08 did not say which year, LLM02:2026 is fine."
    out, after = tx.migrate(text)
    assert "LLM03:2026" in out
    assert "LLM08" in out, "an ambiguous ID must not be guessed at"
    assert not any(r.verdict == tx.STALE for r in after)


def test_migrate_is_idempotent():
    text = "see LLM06:2025 and LLM05:2025"
    once, _ = tx.migrate(text)
    twice, _ = tx.migrate(once)
    assert once == twice


def test_migrate_handles_several_ids_on_one_line():
    """Rewriting left to right would corrupt later offsets on the same line."""
    text = "LLM06:2025 then LLM05:2025 then LLM10:2025"
    out, _ = tx.migrate(text)
    assert out == "LLM03:2026 then LLM10:2026 then LLM06:2026", out


def test_rescoped_entry_is_explained():
    _, detail, _ = tx.classify("LLM", "07", "2025")
    assert "widened" in detail


def test_line_and_column_are_reported():
    refs = list(tx.find_references("first line\nsecond has LLM08 in it"))
    assert len(refs) == 1
    assert refs[0].line == 2
    assert refs[0].raw == "LLM08"


def test_unknown_identifier_does_not_crash():
    refs = list(tx.find_references("LLM99 and ASI42 and MCP77"))
    assert all(r.verdict == tx.STABLE for r in refs)
