"""The quality gate: lint, convert, and fire-test every rule in a workspace.

A rule passes only when it lints clean, compiles for every target that applies
to its log family, and passes its fire-test. Workspace-wide checks add unique
ids/names/titles and flag fixtures that no longer belong to a rule.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import convert, lint
from .firetest import FireTestResult, fire_test
from .workspace import POLARITIES, RuleFile, RuleLoadError, Workspace, load_rule


@dataclass(frozen=True)
class RuleReport:
    path: str
    name: str
    lint: tuple[str, ...]
    conversions: dict[str, str | None]  # applicable target id -> error message, None when OK
    firetest: FireTestResult | None  # None when the file could not be parsed

    @property
    def passed(self) -> bool:
        return (
            not self.lint
            and bool(self.conversions)
            and all(error is None for error in self.conversions.values())
            and self.firetest is not None
            and self.firetest.passed
        )

    def problems(self) -> list[str]:
        """Every failure as ``stage: message``, for terminal and JSON output."""
        out = [f"lint: {msg}" for msg in self.lint]
        if self.firetest is not None and not self.conversions:
            out.append("convert: no conversion target supports this rule's logsource")
        out += [f"{target}: {err}" for target, err in self.conversions.items() if err]
        if self.firetest is not None:
            out += [f"fire-test: {msg}" for msg in self.firetest.failures]
        return out

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "name": self.name,
            "passed": self.passed,
            "lint": list(self.lint),
            "conversions": {t: {"ok": e is None, "error": e} for t, e in self.conversions.items()},
            "firetest": self.firetest.as_dict() if self.firetest else None,
        }


@dataclass(frozen=True)
class CheckReport:
    rules: tuple[RuleReport, ...]
    workspace_issues: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return bool(self.rules) and not self.workspace_issues and all(r.passed for r in self.rules)

    def as_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "rules": [r.as_dict() for r in self.rules],
            "workspace_issues": list(self.workspace_issues),
        }


def check_rule(rule: RuleFile, workspace: Workspace) -> RuleReport:
    conversions: dict[str, str | None] = {}
    for target in convert.targets_for(rule):
        try:
            convert.convert(rule, target.id)
            conversions[target.id] = None
        except convert.ConversionError as exc:
            conversions[target.id] = str(exc)
    return RuleReport(
        path=workspace.display(rule.path),
        name=rule.name,
        lint=tuple(lint.lint_rule(rule)),
        conversions=conversions,
        firetest=fire_test(rule, workspace),
    )


def run_check(workspace: Workspace, paths: Sequence[Path] | None = None) -> CheckReport:
    """Check the rules under ``paths``; with no paths, check the whole workspace."""
    reports: list[RuleReport] = []
    loaded: list[RuleFile] = []
    for path in workspace.rule_paths(paths):
        try:
            rule = load_rule(path)
        except RuleLoadError as exc:
            reports.append(RuleReport(workspace.display(path), path.stem, (str(exc),), {}, None))
            continue
        loaded.append(rule)
        reports.append(check_rule(rule, workspace))

    issues = lint.lint_ruleset(loaded)
    if paths is None:
        if not reports:
            issues.append(f"no rules found under {workspace.display(workspace.rules_dir)}/")
        issues += _orphan_fixtures(workspace)
    return CheckReport(tuple(reports), tuple(issues))


def _orphan_fixtures(workspace: Workspace) -> list[str]:
    owned = {
        workspace.fixture_path(path, polarity).resolve()
        for path in workspace.rule_paths()
        for polarity in POLARITIES
    }
    return [
        f"fixture {workspace.display(path)} has no matching rule"
        for path in workspace.fixture_paths()
        if path.resolve() not in owned
    ]
