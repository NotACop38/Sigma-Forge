"""Unit tests for the correlation evaluator (event_count / value_count + timespan)."""

from __future__ import annotations

from sigma.collection import SigmaCollection

from sigmaforge.evaluate import correlation_triggers

EVENT_COUNT = """
title: base
name: b
logsource: {product: llm_app, category: gateway}
detection: {sel: {llm.prompt|contains: 'x'}, condition: sel}
---
title: burst
id: 00000000-0000-0000-0000-0000000000c1
status: experimental
correlation:
  type: event_count
  rules: [b]
  group-by: [user.id]
  timespan: 10m
  condition: {gte: 3}
"""

VALUE_COUNT = """
title: base
name: b
logsource: {product: llm_app, category: gateway}
detection: {sel: {tool.name|endswith: '_request'}, condition: sel}
---
title: fanout
id: 00000000-0000-0000-0000-0000000000c2
status: experimental
correlation:
  type: value_count
  rules: [b]
  group-by: [user.id]
  timespan: 5m
  condition: {gte: 3, field: tool.target_host}
"""


def _ev(ts, **kw):
    return {"timestamp": ts, **kw}


def test_event_count_triggers_within_window():
    coll = SigmaCollection.from_yaml(EVENT_COUNT)
    events = [
        _ev("2026-06-03T10:00:00Z", **{"user.id": "u1", "llm.prompt": "x"}),
        _ev("2026-06-03T10:01:00Z", **{"user.id": "u1", "llm.prompt": "x"}),
        _ev("2026-06-03T10:02:00Z", **{"user.id": "u1", "llm.prompt": "x"}),
    ]
    assert correlation_triggers(coll, events) is True


def test_event_count_below_threshold_does_not_trigger():
    coll = SigmaCollection.from_yaml(EVENT_COUNT)
    events = [
        _ev("2026-06-03T10:00:00Z", **{"user.id": "u1", "llm.prompt": "x"}),
        _ev("2026-06-03T10:01:00Z", **{"user.id": "u1", "llm.prompt": "x"}),
    ]
    assert correlation_triggers(coll, events) is False


def test_event_count_outside_window_does_not_trigger():
    coll = SigmaCollection.from_yaml(EVENT_COUNT)
    events = [
        _ev("2026-06-03T10:00:00Z", **{"user.id": "u1", "llm.prompt": "x"}),
        _ev("2026-06-03T10:01:00Z", **{"user.id": "u1", "llm.prompt": "x"}),
        _ev("2026-06-03T11:30:00Z", **{"user.id": "u1", "llm.prompt": "x"}),
    ]
    assert correlation_triggers(coll, events) is False


def test_event_count_groups_independently():
    coll = SigmaCollection.from_yaml(EVENT_COUNT)
    # 3 events but across 3 different users -> no single group reaches 3.
    events = [
        _ev("2026-06-03T10:00:00Z", **{"user.id": "u1", "llm.prompt": "x"}),
        _ev("2026-06-03T10:01:00Z", **{"user.id": "u2", "llm.prompt": "x"}),
        _ev("2026-06-03T10:02:00Z", **{"user.id": "u3", "llm.prompt": "x"}),
    ]
    assert correlation_triggers(coll, events) is False


def test_value_count_distinct_hosts():
    coll = SigmaCollection.from_yaml(VALUE_COUNT)
    events = [
        _ev("2026-06-03T10:00:00Z", **{"user.id": "u1", "tool.name": "http_request", "tool.target_host": f"10.0.0.{i}"})
        for i in range(3)
    ]
    assert correlation_triggers(coll, events) is True
    # Same host repeated -> only 1 distinct value -> no trigger.
    same = [
        _ev("2026-06-03T10:00:00Z", **{"user.id": "u1", "tool.name": "http_request", "tool.target_host": "10.0.0.1"})
        for _ in range(5)
    ]
    assert correlation_triggers(coll, same) is False
