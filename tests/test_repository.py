"""The shipped rule set passes its own gate: every rule is linted, compiled, and proven."""

from __future__ import annotations

from pathlib import Path

import pytest
from sigma.rule import SigmaDetectionItem

from sigmaforge.check import check_rule, run_check
from sigmaforge.convert import TARGETS, targets_for
from sigmaforge.workspace import Family, Workspace, load_rule
from tests.support import REPO_ROOT

RULE_PATHS = Workspace(REPO_ROOT).rule_paths()


@pytest.mark.parametrize("path", RULE_PATHS, ids=[p.stem for p in RULE_PATHS])
def test_rule_passes_the_gate(repo: Workspace, path: Path) -> None:
    report = check_rule(load_rule(path), repo)
    assert report.passed, "\n".join(report.problems())


def test_workspace_passes_the_gate(repo: Workspace) -> None:
    report = run_check(repo)
    failures = {r.name: r.problems() for r in report.rules if not r.passed}
    assert report.passed, (report.workspace_issues, failures)


def test_rule_set_exercises_every_family_and_target() -> None:
    rules = [load_rule(path) for path in RULE_PATHS]
    assert {rule.family for rule in rules} == set(Family)
    assert {t.id for rule in rules for t in targets_for(rule)} == set(TARGETS)
    assert any(rule.correlation is not None for rule in rules)


def test_every_rule_file_follows_the_naming_convention() -> None:
    prefixes = {"classic": "win_", "llm": "llm_", "correlation": "llm_"}
    for path in RULE_PATHS:
        assert path.stem.startswith(prefixes[path.parent.name]), path


def _phrases(path: Path) -> list[str]:
    rule = load_rule(REPO_ROOT / path).rules[0]
    (item,) = rule.detection.detections["selection"].detection_items
    assert isinstance(item, SigmaDetectionItem)
    return sorted(str(value) for value in item.value)


def test_burst_correlation_tracks_the_standalone_injection_phrases() -> None:
    """The burst's base rule must match exactly what the single-event rule matches."""
    assert _phrases(Path("rules/correlation/llm_prompt_injection_burst.yml")) == _phrases(
        Path("rules/llm/llm_prompt_injection_phrases.yml")
    )
