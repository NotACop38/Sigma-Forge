"""Lint tests: every rule parses, carries required metadata, and passes validators."""

from __future__ import annotations

from pathlib import Path

import pytest

from sigmaforge import lint
from sigmaforge.convert import iter_rule_files

RULE_FILES = iter_rule_files()
RULE_IDS = [f.stem for f in RULE_FILES]


def test_rules_present():
    assert len(RULE_FILES) >= 6


@pytest.mark.parametrize("rule_path", RULE_FILES, ids=RULE_IDS)
def test_rule_lints_clean(rule_path: Path):
    issues = lint.lint_file(rule_path)
    assert issues == [], f"{rule_path.stem} has lint issues: {issues}"


def test_lint_flags_missing_id():
    bad = """
title: Broken rule
status: experimental
level: low
logsource:
  category: process_creation
  product: windows
detection:
  sel:
    Foo: bar
  condition: sel
"""
    issues = lint.lint_text(bad)
    assert any("id" in i for i in issues), issues


def test_lint_flags_missing_logsource():
    bad = """
title: Broken rule
id: 00000000-0000-0000-0000-0000000000aa
status: experimental
level: low
detection:
  sel:
    Foo: bar
  condition: sel
"""
    issues = lint.lint_text(bad)
    assert issues, "expected a lint/parse error for missing logsource"


def test_lint_flags_invalid_attack_tag():
    bad = """
title: Bad tag rule
id: 00000000-0000-0000-0000-0000000000bb
status: experimental
level: low
logsource:
  category: process_creation
  product: windows
detection:
  sel:
    Image|endswith: '\\\\x.exe'
  condition: sel
tags:
  - attack.not-a-real-tactic
"""
    issues = lint.lint_text(bad)
    assert any("ATT&CK tag" in i for i in issues), issues


def test_lint_flags_unparseable_yaml():
    issues = lint.lint_text("title: [unclosed")
    assert issues and any("parse error" in i for i in issues)
