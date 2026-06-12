"""Drafter tests — fully MOCKED model, ZERO network calls.

Proves the deterministic validator accepts a good rule and rejects bad ones at
the correct stage (lint / convert / fire-test).
"""

from __future__ import annotations

from sigmaforge import draft

GOOD_RULE = """```yaml
title: Drafted Prompt Injection Phrase
id: 7c9e6679-7425-40de-944b-e07fc1f90ae7
status: experimental
description: Detects an override phrase in an LLM prompt.
author: unit-test
level: high
logsource:
  product: llm_app
  category: gateway
detection:
  selection:
    llm.prompt|contains: 'ignore previous instructions'
  condition: selection
tags:
  - attack.initial-access
  - owasp.llm01
  - atlas.t0051
```"""

# Lints fine and converts to BOTH backends, but uses cidr -> the evaluator
# rejects it at the fire-test stage (SigmaCIDRExpression is outside the subset).
UNSUPPORTED_RULE = """```yaml
title: Drafted CIDR Rule
id: 7c9e6679-7425-40de-944b-e07fc1f90ff0
status: experimental
description: Uses an unsupported modifier.
author: unit-test
level: low
logsource:
  product: llm_app
  category: gateway
detection:
  selection:
    request.source_ip|cidr: '10.0.0.0/8'
  condition: selection
```"""

MISSING_ID_RULE = """```yaml
title: No id rule
status: experimental
level: low
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\evil.exe'
  condition: selection
```"""

MALFORMED_RULE = "```yaml\ntitle: [unterminated\n```"


def _fixed(text: str):
    return lambda _threat: text


def test_no_network(monkeypatch):
    """Guard: the real model client must never be invoked when a completion_fn is given."""

    def boom(_threat):
        raise AssertionError("network/model call should not happen")

    monkeypatch.setattr(draft, "_default_completion", boom)
    result = draft.draft_rule("anything", completion_fn=_fixed(GOOD_RULE))
    assert result.accepted


def test_accepts_good_rule(tmp_path):
    out = tmp_path / "drafted.yml"
    result = draft.draft_rule("prompt injection", completion_fn=_fixed(GOOD_RULE), write_path=out)
    assert result.accepted, result.errors
    assert result.splunk and result.kusto
    assert out.exists()


def test_rejects_unsupported_at_fire_test():
    result = draft.draft_rule("cidr thing", completion_fn=_fixed(UNSUPPORTED_RULE))
    assert not result.accepted
    assert any(stage == "fire-test" for stage, _ in result.errors), result.errors


def test_rejects_missing_id_at_lint():
    result = draft.draft_rule("no id", completion_fn=_fixed(MISSING_ID_RULE))
    assert not result.accepted
    assert any(stage == "lint" for stage, _ in result.errors), result.errors


def test_rejects_malformed_yaml():
    result = draft.draft_rule("garbage", completion_fn=_fixed(MALFORMED_RULE))
    assert not result.accepted
    assert result.errors


def test_rejected_rule_not_written(tmp_path):
    out = tmp_path / "should_not_exist.yml"
    draft.draft_rule("bad", completion_fn=_fixed(UNSUPPORTED_RULE), write_path=out)
    assert not out.exists()


OVERBROAD_NOT_RULE = """```yaml
title: Overbroad NOT Rule
id: 7c9e6679-7425-40de-944b-e07fc1f90ab0
status: experimental
description: Matches nearly every event because only a missing benign marker is excluded.
author: unit-test
level: low
logsource:
  product: llm_app
  category: gateway
detection:
  filter:
    llm.prompt|contains: 'benign-marker-never-present'
  condition: not filter
```"""

OVERBROAD_OR_NOT_RULE = """```yaml
title: Overbroad OR NOT Rule
id: 7c9e6679-7425-40de-944b-e07fc1f90ab1
status: experimental
description: Has a valid selection but also an overbroad NOT branch.
author: unit-test
level: low
logsource:
  product: llm_app
  category: gateway
detection:
  selection:
    llm.prompt|contains: 'ignore previous instructions'
  filter:
    llm.prompt|contains: 'benign-marker-never-present'
  condition: selection or not filter
```"""


def test_rejects_rule_that_matches_empty_event():
    result = draft.draft_rule("overbroad", completion_fn=_fixed(OVERBROAD_NOT_RULE))
    assert not result.accepted
    assert ("fire-test", "rule matches an empty event") in result.errors


def test_rejects_or_rule_with_overbroad_not_branch(tmp_path):
    out = tmp_path / "overbroad.yml"
    result = draft.draft_rule(
        "overbroad", completion_fn=_fixed(OVERBROAD_OR_NOT_RULE), write_path=out
    )
    assert not result.accepted
    assert ("fire-test", "rule matches an empty event") in result.errors
    assert not out.exists()


NOT_NULL_RULE = """```yaml
title: NOT Null Rule
id: 7c9e6679-7425-40de-944b-e07fc1f90ab2
status: experimental
description: Matches nearly every event with a non-null prompt.
author: unit-test
level: low
logsource:
  product: llm_app
  category: gateway
detection:
  filter:
    llm.prompt: null
  condition: not filter
```"""

SELF_CONTRADICTORY_NOT_RULE = """```yaml
title: Self Contradictory NOT Rule
id: 7c9e6679-7425-40de-944b-e07fc1f90ab3
status: experimental
description: Can never fire because the same selection is required and excluded.
author: unit-test
level: low
logsource:
  product: llm_app
  category: gateway
detection:
  selection:
    llm.prompt|contains: 'ignore previous instructions'
  condition: selection and not selection
```"""

SELECTION_WITH_NOT_FILTER_RULE = """```yaml
title: Selection With NOT Filter Rule
id: 7c9e6679-7425-40de-944b-e07fc1f90ab4
status: experimental
description: Valid high-signal selection with a benign exclusion.
author: unit-test
level: high
logsource:
  product: llm_app
  category: gateway
detection:
  selection:
    llm.prompt|contains: 'ignore previous instructions'
  filter:
    user.id: 'service-account'
  condition: selection and not filter
```"""

REGEX_SELECTION_RULE = """```yaml
title: Regex Prompt Injection Rule
id: 7c9e6679-7425-40de-944b-e07fc1f90ab5
status: experimental
description: Detects prompt injection phrases with flexible spacing.
author: unit-test
level: high
logsource:
  product: llm_app
  category: gateway
detection:
  selection:
    llm.prompt|re: 'ignore\\s+previous\\s+instructions'
  condition: selection
```"""


def test_rejects_not_null_rule_even_when_empty_event_does_not_match(tmp_path):
    out = tmp_path / "not-null.yml"
    result = draft.draft_rule("not null", completion_fn=_fixed(NOT_NULL_RULE), write_path=out)
    assert not result.accepted
    assert ("fire-test", "synthesized positive event did not fire the rule") in result.errors
    assert not out.exists()


def test_rejects_self_contradictory_not_rule(tmp_path):
    out = tmp_path / "contradictory.yml"
    result = draft.draft_rule(
        "self contradictory", completion_fn=_fixed(SELF_CONTRADICTORY_NOT_RULE), write_path=out
    )
    assert not result.accepted
    assert ("fire-test", "synthesized positive event did not fire the rule") in result.errors
    assert not out.exists()


def test_accepts_selection_with_not_filter_rule():
    result = draft.draft_rule(
        "selection not filter", completion_fn=_fixed(SELECTION_WITH_NOT_FILTER_RULE)
    )
    assert result.accepted, result.errors


def test_accepts_regex_rule_when_positive_synthesis_is_uncertain():
    result = draft.draft_rule("regex", completion_fn=_fixed(REGEX_SELECTION_RULE))
    assert result.accepted, result.errors
