"""Fixture loading and fire-test verdicts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sigmaforge import firetest
from sigmaforge.firetest import FixtureError, evaluate_fixtures, fire_test, load_events
from sigmaforge.workspace import Family, load_rule
from tests.support import (
    WINDOWS_NEGATIVE,
    WINDOWS_POSITIVE,
    WINDOWS_RULE,
    make_rule,
    make_workspace,
)


def write(tmp_path: Path, content: Any, raw: bool = False) -> Path:
    path = tmp_path / "x.positive.json"
    path.write_text(content if raw else json.dumps(content), encoding="utf-8")
    return path


def test_loads_a_list_of_events(tmp_path: Path) -> None:
    assert load_events(write(tmp_path, [{"a": 1}, {"b": 2}])) == [{"a": 1}, {"b": 2}]


@pytest.mark.parametrize(
    ("content", "raw", "message"),
    [
        ("{not json", True, "not valid JSON"),
        ({"a": 1}, False, "non-empty JSON array"),
        ([], False, "non-empty JSON array"),
        ([{"a": 1}, "event"], False, "event #2 is not a JSON object"),
    ],
)
def test_rejects_malformed_fixtures(tmp_path: Path, content: Any, raw: bool, message: str) -> None:
    with pytest.raises(FixtureError, match=message):
        load_events(write(tmp_path, content, raw))


def test_missing_fixture(tmp_path: Path) -> None:
    with pytest.raises(FixtureError, match="missing fixture"):
        load_events(tmp_path / "absent.positive.json")


def test_size_limits_apply_before_parsing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(firetest, "MAX_FIXTURE_BYTES", 8)
    with pytest.raises(FixtureError, match="the limit is 8"):
        load_events(write(tmp_path, "[{} , {}, {}]", raw=True))


def test_event_count_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(firetest, "MAX_FIXTURE_EVENTS", 2)
    with pytest.raises(FixtureError, match="3 events; the limit is 2"):
        load_events(write(tmp_path, [{}, {}, {}]))


@pytest.mark.parametrize(
    ("event", "message"),
    [
        ({"llm.promt": "typo"}, "unknown field 'llm.promt'"),
        ({"llm.prompt_tokens": "12"}, "'llm.prompt_tokens' must be int"),
        ({"llm.prompt_tokens": True}, "'llm.prompt_tokens' must be int"),
        ({"timestamp": "noon"}, "not ISO-8601"),
        ({"llm": {"prompt": 5}}, "'llm.prompt' must be str"),
    ],
)
def test_llm_fixtures_must_fit_the_schema(
    tmp_path: Path, event: dict[str, Any], message: str
) -> None:
    with pytest.raises(FixtureError, match=message):
        load_events(write(tmp_path, [event]), family=Family.LLM)


def test_reports_which_events_failed() -> None:
    rule = make_rule(WINDOWS_RULE)
    result = evaluate_fixtures(
        rule,
        {
            "positive": [*WINDOWS_POSITIVE, *WINDOWS_NEGATIVE],
            "negative": [*WINDOWS_NEGATIVE, *WINDOWS_POSITIVE],
        },
    )
    assert not result.passed
    assert result.positives == (1, 2)
    assert result.negatives == (1, 2)
    assert result.failures == ("positive event #2 did not fire", "negative event #2 fired")


def test_fire_test_reads_fixtures_from_the_workspace(tmp_path: Path) -> None:
    workspace = make_workspace(
        tmp_path,
        {"classic/win_whoami": WINDOWS_RULE},
        {
            "classic/win_whoami.positive": WINDOWS_POSITIVE,
            "classic/win_whoami.negative": WINDOWS_NEGATIVE,
        },
    )
    result = fire_test(load_rule(tmp_path / "rules/classic/win_whoami.yml"), workspace)
    assert result.passed
    assert result.as_dict()["positives"] == {"fired": 1, "total": 1}


def test_fire_test_reports_every_missing_fixture(tmp_path: Path) -> None:
    workspace = make_workspace(tmp_path, {"classic/win_whoami": WINDOWS_RULE})
    result = fire_test(load_rule(tmp_path / "rules/classic/win_whoami.yml"), workspace)
    assert result.failures == (
        "missing fixture win_whoami.positive.json",
        "missing fixture win_whoami.negative.json",
    )


def test_unsupported_rules_fail_the_fire_test_instead_of_crashing() -> None:
    rule = make_rule(
        WINDOWS_RULE.replace("Image|endswith: '\\whoami.exe'", "User|fieldref: TargetUser")
    )
    result = evaluate_fixtures(rule, {"positive": WINDOWS_POSITIVE, "negative": WINDOWS_NEGATIVE})
    assert not result.passed
    assert "SigmaFieldReference" in result.failures[0]
