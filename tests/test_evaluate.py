"""Fire-test every rule: positive fixtures must match, negative fixtures must not."""

from __future__ import annotations

from pathlib import Path

import pytest

from sigmaforge import evaluate as ev
from sigmaforge.convert import iter_rule_files

RULE_FILES = iter_rule_files()
RULE_IDS = [f.stem for f in RULE_FILES]


@pytest.mark.parametrize("rule_path", RULE_FILES, ids=RULE_IDS)
def test_rule_has_fixtures(rule_path: Path):
    report = ev.fire_test(rule_path)
    assert not report.skipped, f"{rule_path.stem} has no positive/negative sample logs"
    assert report.positives_total > 0, f"{rule_path.stem} has no positive fixtures"
    assert report.negatives_total > 0, f"{rule_path.stem} has no negative fixtures"


@pytest.mark.parametrize("rule_path", RULE_FILES, ids=RULE_IDS)
def test_positives_match_and_negatives_do_not(rule_path: Path):
    report = ev.fire_test(rule_path)
    assert report.positives_matched == report.positives_total, (
        f"{rule_path.stem}: only {report.positives_matched}/{report.positives_total} "
        "positive events fired"
    )
    assert report.negatives_clean == report.negatives_total, (
        f"{rule_path.stem}: {report.negatives_total - report.negatives_clean} negative "
        "event(s) incorrectly fired"
    )
    assert report.passed


def test_unsupported_feature_raises():
    """The evaluator must refuse constructs outside the documented subset."""
    rule_yaml = """
title: Unsupported CIDR
id: 00000000-0000-0000-0000-0000000000ff
logsource:
  category: process_creation
  product: windows
detection:
  sel:
    SourceIp|cidr: '10.0.0.0/8'
  condition: sel
"""
    from sigma.collection import SigmaCollection

    parsed = SigmaCollection.from_yaml(rule_yaml).rules[0]
    with pytest.raises(ev.UnsupportedFeatureError):
        ev.matches(parsed, {"SourceIp": "10.1.2.3"})
