"""Manual rendering tests: section filtering and roff output."""

from __future__ import annotations

from rich.console import Console

import coniugata.modules  # noqa: F401  (populate the source registry)
from coniugata.manual import render_manual, render_roff, sections


def test_sections_cover_expected_topics():
    titles = [title for title, _ in sections()]
    for expected in (
        "NAME",
        "SYNOPSIS",
        "DESCRIPTION",
        "COMMANDS",
        "SCAN OPTIONS",
        "PROFILES",
        "SOURCES",
        "CONFIGURATION",
        "EXAMPLES",
        "EXIT STATUS",
    ):
        assert expected in titles


def test_sources_section_lists_registered_modules():
    sources = dict(sections())["SOURCES"]
    assert any(block.startswith("crtsh:") for block in sources)
    assert any(block.startswith("urlscan:") for block in sources)


def test_manual_section_filter():
    console = Console(record=True, width=100)
    assert render_manual(console, "scan") is True
    output = console.export_text()
    assert "SCAN OPTIONS" in output
    assert "DESCRIPTION" not in output
    assert render_manual(console, "no-such-section") is False


def test_roff_is_well_formed():
    roff = render_roff()
    assert roff.startswith(".TH CONIUGATA 1 ")
    assert "\n.SH NAME\n" in roff
    assert "\n.SH CONFIGURATION\n" in roff
    assert roff.endswith("\n")
