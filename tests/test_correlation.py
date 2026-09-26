"""Correlation semantics: counting, grouping, nulls, timestamps, and window models."""

from __future__ import annotations

from typing import Any

import pytest

from sigmaforge import evaluate
from sigmaforge.evaluate import CorrelationMatcher, UnsupportedFeatureError, WindowModel
from sigmaforge.firetest import evaluate_fixtures
from tests.support import make_rule

BASE = """
title: Injection attempt
id: 7c9e6679-7425-40de-944b-e07fc1f90b01
name: attempt
status: experimental
description: base
author: tests
date: 2026-01-01
references: [https://atlas.mitre.org/techniques/AML.T0051]
logsource: {product: llm_app, category: gateway}
detection: {sel: {llm.prompt|contains: 'inject'}, condition: sel}
level: informational
tags: [owasp.llm01]
"""


def correlation(body: str, base: str = BASE) -> CorrelationMatcher:
    text = f"""{base}---
title: Correlation
id: 7c9e6679-7425-40de-944b-e07fc1f90b02
status: experimental
description: correlation
author: tests
date: 2026-01-01
correlation:
{body}
level: high
tags: [owasp.llm01]
"""
    rule = make_rule(text)
    assert rule.correlation is not None
    return CorrelationMatcher(rule.correlation)


BURST = correlation("  type: event_count\n  rules: [attempt]\n  group-by: [user.id]\n"
                    "  timespan: 10m\n  condition: {gte: 3}")  # fmt: skip
FANOUT_BASE = BASE.replace("llm.prompt|contains: 'inject'", "tool.name: http_request")
FANOUT = correlation(
    "  type: value_count\n  rules: [attempt]\n  group-by: [user.id]\n"
    "  timespan: 5m\n  condition: {gte: 3, field: tool.target_host}",
    FANOUT_BASE,
)


def attempt(minute: float, user: str | None = "u1", prompt: str = "inject") -> dict[str, Any]:
    seconds = round(minute * 60)
    event = {"timestamp": f"2026-06-03T14:{seconds // 60:02d}:{seconds % 60:02d}Z"}
    event["llm.prompt"] = prompt
    if user is not None:
        event["user.id"] = user
    return event


def request(minute: int, host: str | None, user: str = "u1") -> dict[str, Any]:
    event: dict[str, Any] = {
        "timestamp": f"2026-06-03T15:{minute:02d}:00Z",
        "user.id": user,
        "tool.name": "http_request",
    }
    if host is not None:
        event["tool.target_host"] = host
    return event


BOTH = list(WindowModel)


@pytest.mark.parametrize("window", BOTH)
def test_event_count_threshold(window: WindowModel) -> None:
    assert BURST.triggers([attempt(0), attempt(1), attempt(2)], window)
    assert not BURST.triggers([attempt(0), attempt(1)], window)


@pytest.mark.parametrize("window", BOTH)
def test_only_matching_events_count(window: WindowModel) -> None:
    events = [attempt(0), attempt(1), attempt(2, prompt="weather")]
    assert not BURST.triggers(events, window)


@pytest.mark.parametrize("window", BOTH)
def test_groups_are_counted_independently(window: WindowModel) -> None:
    assert not BURST.triggers([attempt(0, "u1"), attempt(1, "u2"), attempt(2, "u3")], window)


@pytest.mark.parametrize("window", BOTH)
def test_events_without_a_group_by_value_are_dropped(window: WindowModel) -> None:
    """Like Splunk's `stats ... by user_id`, which drops events lacking user_id."""
    assert not BURST.triggers([attempt(0, None), attempt(1, None), attempt(2, None)], window)


@pytest.mark.parametrize("window", BOTH)
def test_events_outside_the_timespan_do_not_combine(window: WindowModel) -> None:
    assert not BURST.triggers([attempt(0), attempt(1), attempt(30)], window)


def test_windows_are_half_open() -> None:
    """[t, t + 10m): an event exactly one timespan later starts a new window."""
    assert not BURST.triggers([attempt(0), attempt(5), attempt(10)], WindowModel.SLIDING)
    assert BURST.triggers([attempt(0), attempt(5), attempt(9.99)], WindowModel.SLIDING)


def test_sliding_and_tumbling_windows_disagree_on_a_straddling_burst() -> None:
    """14:09, 14:10, 14:11 fit one sliding 10m window but split across two fixed buckets."""
    straddle = [attempt(9), attempt(10), attempt(11)]
    assert BURST.triggers(straddle, WindowModel.SLIDING)
    assert not BURST.triggers(straddle, WindowModel.TUMBLING)


def test_fire_test_fails_scenarios_whose_verdict_depends_on_the_window() -> None:
    text = f"""{BASE}---
title: Burst
id: 7c9e6679-7425-40de-944b-e07fc1f90b03
status: experimental
description: burst
author: tests
date: 2026-01-01
correlation: {{type: event_count, rules: [attempt], group-by: [user.id], timespan: 10m,
  condition: {{gte: 3}}}}
level: high
tags: [owasp.llm01]
"""
    rule = make_rule(text)
    result = evaluate_fixtures(
        rule, {"positive": [attempt(9), attempt(10), attempt(11)], "negative": [attempt(0)]}
    )
    assert result.failures == ("positive scenario did not trigger under tumbling windows",)
    assert result.positives == (0, 1)
    assert result.negatives == (1, 1)


@pytest.mark.parametrize("window", BOTH)
def test_value_count_counts_distinct_non_null_values(window: WindowModel) -> None:
    assert FANOUT.triggers([request(0, "a"), request(1, "b"), request(2, "c")], window)
    assert not FANOUT.triggers([request(0, "a"), request(1, "a"), request(2, "b")], window)
    assert not FANOUT.triggers([request(0, "a"), request(1, "b"), request(2, None)], window)


def test_value_count_sliding_window_forgets_expired_values() -> None:
    events = [request(0, "a"), request(1, "b"), request(6, "c"), request(7, "d")]
    assert not FANOUT.triggers(events, WindowModel.SLIDING)
    events.append(request(8, "e"))
    assert FANOUT.triggers(events, WindowModel.SLIDING)


def test_naive_timestamps_are_utc() -> None:
    assert evaluate.event_time({"timestamp": "2026-06-03T14:00:00"}) == evaluate.event_time(
        {"timestamp": "2026-06-03T14:00:00+00:00"}
    )


@pytest.mark.parametrize("value", [None, "yesterday", 1780000000])
def test_correlations_require_iso8601_timestamps(value: Any) -> None:
    event = attempt(0)
    event["timestamp"] = value
    with pytest.raises(UnsupportedFeatureError, match="timestamp"):
        BURST.triggers([event], WindowModel.SLIDING)


def test_group_size_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(evaluate, "MAX_CORRELATION_GROUP_EVENTS", 3)
    with pytest.raises(UnsupportedFeatureError, match="maximum"):
        BURST.triggers([attempt(i / 10) for i in range(4)], WindowModel.SLIDING)


def test_large_groups_are_evaluated_in_linear_time() -> None:
    events = [request(0, f"10.0.{i // 250}.{i % 250}") for i in range(3_000)]
    assert FANOUT.triggers(events, WindowModel.SLIDING)


TWO_BASES = (
    BASE
    + "---\n"
    + BASE.replace("name: attempt", "name: attempt2")
    .replace("e07fc1f90b01", "e07fc1f90b09")
    .replace("title: Injection attempt", "title: Second attempt")
)


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (
            "  type: temporal\n  rules: [attempt, attempt2]\n  group-by: [user.id]\n  timespan: 5m",
            "unsupported correlation type: TEMPORAL",
        ),
        (
            "  type: value_sum\n  rules: [attempt]\n  group-by: [user.id]\n  timespan: 5m\n"
            "  condition: {gte: 3, field: llm.prompt_tokens}",
            "unsupported correlation type: VALUE_SUM",
        ),
        (
            "  type: event_count\n  rules: [attempt, attempt2]\n  group-by: [uid]\n  timespan: 5m\n"
            "  aliases: {uid: {attempt: user.id, attempt2: user.id}}\n  condition: {gte: 3}",
            "aliases are not supported",
        ),
        (
            "  type: event_count\n  rules: [attempt]\n  group-by: [user.id]\n  timespan: 0s\n"
            "  condition: {gte: 3}",
            "timespan must be positive",
        ),
    ],
    ids=["temporal", "value_sum", "aliases", "zero-timespan"],
)
def test_unsupported_correlations_are_refused(body: str, message: str) -> None:
    with pytest.raises(UnsupportedFeatureError, match=message):
        correlation(body, TWO_BASES)


def test_only_referenced_base_rules_count() -> None:
    """An unreferenced rule in the same file must not feed the correlation."""
    bases = TWO_BASES.rsplit("llm.prompt|contains: 'inject'", 1)
    matcher = correlation(
        "  type: event_count\n  rules: [attempt2]\n  group-by: [user.id]\n  timespan: 10m\n"
        "  condition: {gte: 3}",
        "llm.prompt|contains: 'weather'".join(bases),
    )
    injections = [attempt(0), attempt(1), attempt(2)]
    weather = [attempt(i, prompt="weather") for i in range(3)]
    assert not matcher.triggers(injections, WindowModel.SLIDING)
    assert matcher.triggers(weather, WindowModel.SLIDING)


@pytest.mark.parametrize("window", BOTH)
def test_values_group_and_count_as_strings_like_splunk(window: WindowModel) -> None:
    events = [request(0, "a", user="1"), request(1, "b", user="1"), request(2, "c", user="1")]
    events[1]["user.id"] = 1  # the same user, logged as a number
    assert FANOUT.triggers(events, window)


def test_correlation_fields_must_be_scalar() -> None:
    event = attempt(0)
    event["user.id"] = ["u1", "u2"]
    with pytest.raises(UnsupportedFeatureError, match="must hold a scalar value"):
        BURST.triggers([event], WindowModel.SLIDING)
