"""Conversion tests: every rule converts for each applicable target and matches its golden."""

from __future__ import annotations

from pathlib import Path

import pytest

from sigmaforge import convert as convert_mod

GOLDEN_DIR = Path(__file__).resolve().parent / "golden"
RULE_FILES = convert_mod.iter_rule_files()

# Build the (rule, target) matrix from each rule's kind.
CASES: list[tuple[Path, str]] = []
for _f in RULE_FILES:
    for _t in convert_mod.targets_for(convert_mod.rule_kind(_f)):
        CASES.append((_f, _t))
CASE_IDS = [f"{f.stem}-{t}" for f, t in CASES]


def test_rules_exist():
    assert RULE_FILES, "no rule files discovered under rules/"


def test_cli_rejects_unknown_target():
    from typer.testing import CliRunner

    from sigmaforge.cli import app

    result = CliRunner().invoke(app, ["convert", "--all", "--target", "splnuk"])
    assert result.exit_code == 2, result.output
    assert "Unknown target" in result.output


@pytest.mark.parametrize(("rule_path", "target"), CASES, ids=CASE_IDS)
def test_converts_for_target(rule_path: Path, target: str):
    conv = convert_mod.convert_file(rule_path)
    assert conv.query(target), f"{rule_path.stem} produced empty {target} output"


@pytest.mark.parametrize(("rule_path", "target"), CASES, ids=CASE_IDS)
def test_matches_golden(rule_path: Path, target: str):
    conv = convert_mod.convert_file(rule_path)
    golden = GOLDEN_DIR / f"{conv.name}.{target}.txt"
    assert golden.exists(), (
        f"missing golden snapshot {golden.name}; run `make golden` to create it"
    )
    expected = golden.read_text(encoding="utf-8").strip()
    assert conv.query(target).strip() == expected, (
        f"{conv.name} {target} drifted from golden; run `make golden` to update"
    )
