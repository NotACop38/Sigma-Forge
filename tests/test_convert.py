"""Conversion tests: every rule converts without error and matches its golden snapshot."""

from __future__ import annotations

from pathlib import Path

import pytest

from sigmaforge import convert as convert_mod

GOLDEN_DIR = Path(__file__).resolve().parent / "golden"
RULE_FILES = convert_mod.iter_rule_files()
RULE_IDS = [f.stem for f in RULE_FILES]


def test_rules_exist():
    assert RULE_FILES, "no rule files discovered under rules/"


@pytest.mark.parametrize("rule_path", RULE_FILES, ids=RULE_IDS)
def test_converts_to_both_backends(rule_path: Path):
    conv = convert_mod.convert_file(rule_path)
    for target in convert_mod.TARGETS:
        query = conv.query(target)
        assert query, f"{rule_path.stem} produced empty {target} output"


@pytest.mark.parametrize("rule_path", RULE_FILES, ids=RULE_IDS)
def test_matches_golden(rule_path: Path):
    conv = convert_mod.convert_file(rule_path)
    for target in convert_mod.TARGETS:
        golden = GOLDEN_DIR / f"{conv.name}.{target}.txt"
        assert golden.exists(), (
            f"missing golden snapshot {golden.name}; run `make golden` to create it"
        )
        expected = golden.read_text(encoding="utf-8").strip()
        actual = conv.query(target).strip()
        assert actual == expected, (
            f"{conv.name} {target} drifted from golden snapshot; run `make golden` to update"
        )
