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


def test_rule_discovery_includes_yaml_and_unparseable_files(tmp_path: Path):
    valid_yml = tmp_path / "valid_rule.yml"
    valid_yaml = tmp_path / "valid_rule.yaml"
    malformed_yml = tmp_path / "malformed_rule.yml"

    valid_rule = """
title: Test Rule
id: 11111111-1111-1111-1111-111111111111
status: test
logsource:
  category: process_creation
detection:
  selection:
    Image: cmd.exe
  condition: selection
""".strip()
    valid_yml.write_text(valid_rule, encoding="utf-8")
    valid_yaml.write_text(valid_rule, encoding="utf-8")
    malformed_yml.write_text("title: [unterminated\n", encoding="utf-8")

    discovered = {p.name for p in convert_mod.iter_rule_files([tmp_path])}

    assert discovered == {valid_yml.name, valid_yaml.name, malformed_yml.name}


def test_convert_check_fails_on_unparseable_rule(tmp_path: Path):
    from typer.testing import CliRunner

    from sigmaforge.cli import app

    malformed_yml = tmp_path / "malformed_rule.yml"
    malformed_yml.write_text("title: [unterminated\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["convert", str(tmp_path), "--check", "--target", "splunk"])

    assert result.exit_code == 1, result.output
    assert "1 rule(s) failed to convert" in result.output


@pytest.mark.parametrize(("rule_path", "target"), CASES, ids=CASE_IDS)
def test_converts_for_target(rule_path: Path, target: str):
    conv = convert_mod.convert_file(rule_path)
    assert conv.query(target), f"{rule_path.stem} produced empty {target} output"


def test_no_stale_golden_snapshots():
    """Every golden corresponds to a live (rule, target) pair; run `make golden` to prune."""
    expected = {f"{f.stem}.{t}.txt" for f, t in CASES}
    actual = {p.name for p in GOLDEN_DIR.glob("*.txt")}
    stale = actual - expected
    assert not stale, f"stale golden snapshot(s) with no matching rule/target: {sorted(stale)}"


@pytest.mark.parametrize(("rule_path", "target"), CASES, ids=CASE_IDS)
def test_matches_golden(rule_path: Path, target: str):
    conv = convert_mod.convert_file(rule_path)
    golden = GOLDEN_DIR / f"{conv.name}.{target}.txt"
    assert golden.exists(), f"missing golden snapshot {golden.name}; run `make golden` to create it"
    expected = golden.read_text(encoding="utf-8").strip()
    assert conv.query(target).strip() == expected, (
        f"{conv.name} {target} drifted from golden; run `make golden` to update"
    )
