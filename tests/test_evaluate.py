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
    parsed = _rule_from_yaml(rule_yaml)
    with pytest.raises(ev.UnsupportedFeatureError):
        ev.matches(parsed, {"SourceIp": "10.1.2.3"})


def _rule_from_yaml(rule_yaml: str):
    from sigma.collection import SigmaCollection

    return SigmaCollection.from_yaml(rule_yaml).rules[0]


def test_regex_detection_uses_plain_pattern():
    """Sigma |re values should still work for normal bounded expressions."""
    rule_yaml = """
title: Regex Detection
id: 00000000-0000-0000-0000-000000000101
logsource:
  category: process_creation
  product: windows
detection:
  sel:
    Message|re: '^hello-[0-9]+$'
  condition: sel
"""
    parsed = _rule_from_yaml(rule_yaml)

    assert ev.matches(parsed, {"Message": "hello-123"})
    assert not ev.matches(parsed, {"Message": "hello-world"})


def test_oversized_fixture_rejected_before_parsing(tmp_path, monkeypatch):
    """The byte cap must trip on file size alone, before json.loads sees the data."""
    monkeypatch.setattr(ev, "MAX_FIXTURE_BYTES", 16, raising=True)
    big = tmp_path / "big.positive.json"
    big.write_text('[{"CommandLine": "x"}]', encoding="utf-8")

    with pytest.raises(ev.UnsupportedFeatureError, match="maximum supported fixture size"):
        ev._load_events(big)


def test_regex_detection_times_out_catastrophic_backtracking(monkeypatch):
    """Rule-controlled regexes should fail closed instead of hanging CI."""
    monkeypatch.setattr(ev, "REGEX_TIMEOUT_SECONDS", 0.01, raising=False)
    rule_yaml = """
title: Regex Timeout
id: 00000000-0000-0000-0000-000000000102
logsource:
  category: process_creation
  product: windows
detection:
  sel:
    Message|re: '^(a+)+$'
  condition: sel
"""
    parsed = _rule_from_yaml(rule_yaml)

    with pytest.raises(ev.UnsupportedFeatureError, match="regular expression evaluation timed out"):
        ev.matches(parsed, {"Message": "a" * 20 + "!"})
