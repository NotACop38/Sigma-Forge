"""The gate: per-rule reports and workspace-wide checks."""

from __future__ import annotations

import json
from pathlib import Path

from sigmaforge.check import run_check
from tests.support import (
    WINDOWS_NEGATIVE,
    WINDOWS_POSITIVE,
    WINDOWS_RULE,
    make_workspace,
)

FIXTURES = {
    "classic/win_whoami.positive": WINDOWS_POSITIVE,
    "classic/win_whoami.negative": WINDOWS_NEGATIVE,
}


def test_a_clean_workspace_passes(tmp_path: Path) -> None:
    report = run_check(make_workspace(tmp_path, {"classic/win_whoami": WINDOWS_RULE}, FIXTURES))
    assert report.passed
    (rule,) = report.rules
    assert rule.path == "rules/classic/win_whoami.yml"
    assert rule.conversions == {"splunk": None, "defender": None, "sentinel": None}
    assert rule.problems() == []
    json.dumps(report.as_dict())  # the --json output must serialize


def test_unparseable_rules_fail_without_crashing(tmp_path: Path) -> None:
    rules = {"classic/win_whoami": WINDOWS_RULE, "classic/win_broken": "title: ["}
    report = run_check(make_workspace(tmp_path, rules, FIXTURES))
    assert not report.passed
    broken = next(r for r in report.rules if r.name == "win_broken")
    assert broken.firetest is None
    assert broken.problems()[0].startswith("lint: invalid YAML")


def test_every_stage_reports_its_failures(tmp_path: Path) -> None:
    rule = WINDOWS_RULE.replace("Image|endswith", "Image|cased").replace("attack.t1033", "attack.x")
    fixtures = {
        "classic/win_whoami.positive": WINDOWS_NEGATIVE,
        "classic/win_whoami.negative": WINDOWS_POSITIVE,
    }
    report = run_check(make_workspace(tmp_path, {"classic/win_whoami": rule}, fixtures))
    problems = report.rules[0].problems()
    assert any(p.startswith("lint: ") for p in problems)
    assert any(p.startswith("splunk: Splunk SPL:") for p in problems)
    assert any(p.startswith("fire-test: positive event #1 did not fire") for p in problems)


def test_unsupported_logsources_have_no_targets(tmp_path: Path) -> None:
    rule = WINDOWS_RULE.replace("product: windows", "product: linux")
    report = run_check(make_workspace(tmp_path, {"classic/win_whoami": rule}, FIXTURES))
    assert "convert: no conversion target supports this rule's logsource" in (
        report.rules[0].problems()
    )


def test_orphaned_fixtures_are_reported(tmp_path: Path) -> None:
    fixtures = {**FIXTURES, "classic/win_retired.positive": WINDOWS_POSITIVE}
    report = run_check(make_workspace(tmp_path, {"classic/win_whoami": WINDOWS_RULE}, fixtures))
    assert report.workspace_issues == (
        "fixture sample_logs/classic/win_retired.positive.json has no matching rule",
    )


def test_duplicate_titles_across_files_are_reported(tmp_path: Path) -> None:
    copy = WINDOWS_RULE.replace("f90a01", "f90a02")
    fixtures = {
        **FIXTURES,
        "classic/win_copy.positive": WINDOWS_POSITIVE,
        "classic/win_copy.negative": WINDOWS_NEGATIVE,
    }
    workspace = make_workspace(
        tmp_path, {"classic/win_whoami": WINDOWS_RULE, "classic/win_copy": copy}, fixtures
    )
    report = run_check(workspace)
    assert not report.passed
    assert "duplicate rule title 'Whoami Execution' in win_copy, win_whoami" in (
        report.workspace_issues
    )


def test_an_empty_workspace_fails(tmp_path: Path) -> None:
    report = run_check(make_workspace(tmp_path, {}))
    assert not report.passed
    assert report.workspace_issues == ("no rules found under rules/",)


def test_explicit_paths_skip_workspace_wide_checks(tmp_path: Path) -> None:
    fixtures = {**FIXTURES, "classic/win_retired.positive": WINDOWS_POSITIVE}
    workspace = make_workspace(tmp_path, {"classic/win_whoami": WINDOWS_RULE}, fixtures)
    report = run_check(workspace, [tmp_path / "rules/classic/win_whoami.yml"])
    assert report.passed
