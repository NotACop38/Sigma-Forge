"""Fire-test rules against their synthetic fixtures.

Every rule file ships two fixture files (see :mod:`sigmaforge.workspace`):

* plain rules: each event in ``<name>.positive.json`` must fire the rule, and
  no event in ``<name>.negative.json`` may fire it;
* correlation rules: each fixture file is one scenario. The positive scenario
  must trigger the correlation, and the negative scenario must not, under
  *both* window models (sliding windows, and the fixed buckets the generated
  SPL uses). A scenario whose verdict depends on the window model fails, so a
  passing fixture proves the behaviour regardless of how the SIEM buckets time.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import llm_schema
from .evaluate import CorrelationMatcher, RuleMatcher, UnsupportedFeatureError, WindowModel
from .workspace import POLARITIES, Family, Polarity, RuleFile, Workspace

MAX_FIXTURE_BYTES = 5 * 1024 * 1024
MAX_FIXTURE_EVENTS = 5_000


class FixtureError(ValueError):
    """A fixture file is missing, malformed, or violates the event schema."""


@dataclass(frozen=True)
class FireTestResult:
    """Outcome of fire-testing one rule file.

    ``positives`` / ``negatives`` count *events* for plain rules and *scenarios*
    for correlations: ``(fired, total)`` and ``(silent, total)``.
    """

    rule: str
    correlation: bool
    positives: tuple[int, int] = (0, 0)
    negatives: tuple[int, int] = (0, 0)
    failures: tuple[str, ...] = field(default_factory=tuple)

    @property
    def passed(self) -> bool:
        return not self.failures

    def as_dict(self) -> dict[str, Any]:
        return {
            "correlation": self.correlation,
            "positives": {"fired": self.positives[0], "total": self.positives[1]},
            "negatives": {"silent": self.negatives[0], "total": self.negatives[1]},
            "failures": list(self.failures),
            "passed": self.passed,
        }


def load_events(path: Path, *, family: Family | None = None) -> list[dict[str, Any]]:
    """Load a fixture file: a non-empty JSON array of event objects."""
    if not path.is_file():
        raise FixtureError(f"missing fixture {path.name}")
    size = path.stat().st_size
    if size > MAX_FIXTURE_BYTES:  # checked before parsing so one huge value cannot exhaust memory
        raise FixtureError(f"{path.name} is {size} bytes; the limit is {MAX_FIXTURE_BYTES}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FixtureError(f"{path.name} is not valid JSON: {exc}") from exc
    return validate_events(data, family=family, label=path.name)


def validate_events(data: Any, *, family: Family | None, label: str) -> list[dict[str, Any]]:
    """Check decoded fixture data: a non-empty list of objects that fit the family's schema."""
    if not isinstance(data, list) or not data:
        raise FixtureError(f"{label} must be a non-empty JSON array of events")
    if len(data) > MAX_FIXTURE_EVENTS:
        raise FixtureError(f"{label} has {len(data)} events; the limit is {MAX_FIXTURE_EVENTS}")
    for index, event in enumerate(data, start=1):
        if not isinstance(event, dict):
            raise FixtureError(f"{label} event #{index} is not a JSON object")
        if family is Family.LLM:
            problems = llm_schema.validate_event(event)
            if problems:
                raise FixtureError(f"{label} event #{index}: {'; '.join(problems)}")
    return data


def evaluate_fixtures(
    rule: RuleFile, fixtures: Mapping[Polarity, list[dict[str, Any]]]
) -> FireTestResult:
    """Fire-test ``rule`` against already-loaded positive and negative events."""
    positives, negatives = fixtures["positive"], fixtures["negative"]
    correlation = rule.correlation
    try:
        if correlation is not None:
            matcher = CorrelationMatcher(correlation)
            triggered = {w: matcher.triggers(positives, w) for w in WindowModel}
            leaked = {w: matcher.triggers(negatives, w) for w in WindowModel}
            failures = [
                f"positive scenario did not trigger under {w} windows"
                for w in WindowModel
                if not triggered[w]
            ]
            failures += [
                f"negative scenario triggered under {w} windows" for w in WindowModel if leaked[w]
            ]
            fired, silent = int(all(triggered.values())), int(not any(leaked.values()))
            return FireTestResult(rule.name, True, (fired, 1), (silent, 1), tuple(failures))

        if len(rule.rules) != 1:
            raise UnsupportedFeatureError("a rule file without a correlation must hold one rule")
        matches = RuleMatcher(rule.rules[0])
        missed = [i for i, event in enumerate(positives, start=1) if not matches(event)]
        noisy = [i for i, event in enumerate(negatives, start=1) if matches(event)]
    except UnsupportedFeatureError as exc:
        return FireTestResult(rule.name, correlation is not None, failures=(str(exc),))

    failures = [f"positive event #{i} did not fire" for i in missed]
    failures += [f"negative event #{i} fired" for i in noisy]
    return FireTestResult(
        rule.name,
        False,
        (len(positives) - len(missed), len(positives)),
        (len(negatives) - len(noisy), len(negatives)),
        tuple(failures),
    )


def fire_test(rule: RuleFile, workspace: Workspace) -> FireTestResult:
    """Load ``rule``'s fixture files from ``workspace`` and fire-test it."""
    fixtures: dict[Polarity, list[dict[str, Any]]] = {}
    errors = []
    for polarity in POLARITIES:
        try:
            path = workspace.fixture_path(rule.path, polarity)
            fixtures[polarity] = load_events(path, family=rule.family)
        except FixtureError as exc:
            errors.append(str(exc))
    if errors:
        return FireTestResult(rule.name, rule.correlation is not None, failures=tuple(errors))
    return evaluate_fixtures(rule, fixtures)
