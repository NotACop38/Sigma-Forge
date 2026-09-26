"""Workspace discovery, rule discovery, and rule parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from sigmaforge.workspace import Family, RuleLoadError, Workspace, load_rule, parse_rule
from tests.support import WINDOWS_RULE, make_rule, make_workspace, rule_yaml


def test_discover_walks_up_to_the_directory_with_rules(tmp_path: Path) -> None:
    (tmp_path / "rules").mkdir()
    nested = tmp_path / "docs" / "deep"
    nested.mkdir(parents=True)
    assert Workspace.discover(nested).root == tmp_path.resolve()


def test_discover_falls_back_to_the_start_directory(tmp_path: Path) -> None:
    assert Workspace.discover(tmp_path).root == tmp_path.resolve()


def test_rule_discovery(tmp_path: Path) -> None:
    workspace = make_workspace(
        tmp_path,
        {"classic/a": WINDOWS_RULE, "llm/b": WINDOWS_RULE, "classic/broken": "title: ["},
    )
    (tmp_path / "rules" / "classic" / "c.yaml").write_text(WINDOWS_RULE, encoding="utf-8")
    (tmp_path / "rules" / "classic" / "notes.txt").write_text("ignored", encoding="utf-8")

    names = [p.name for p in workspace.rule_paths()]
    assert names == ["a.yml", "broken.yml", "c.yaml", "b.yml"]
    only = workspace.rule_paths([tmp_path / "rules/llm", tmp_path / "rules/llm/b.yml"])
    assert [p.name for p in only] == ["b.yml"]


@pytest.mark.parametrize(
    ("relative", "message"),
    [("rules/missing.yml", "no such file"), ("rules/notes.txt", "not a .yml/.yaml")],
)
def test_rule_discovery_rejects_bad_paths(tmp_path: Path, relative: str, message: str) -> None:
    workspace = make_workspace(tmp_path, {})
    (tmp_path / "rules" / "notes.txt").write_text("x", encoding="utf-8")
    with pytest.raises(RuleLoadError, match=message):
        workspace.rule_paths([tmp_path / relative])


def test_rule_discovery_needs_a_rules_directory(tmp_path: Path) -> None:
    with pytest.raises(RuleLoadError, match="no rules/ directory"):
        Workspace(tmp_path).rule_paths()


def test_fixture_paths_mirror_rule_paths(tmp_path: Path) -> None:
    workspace = Workspace(tmp_path)
    rule_path = tmp_path / "rules" / "llm" / "llm_x.yml"
    assert workspace.fixture_path(rule_path, "negative") == (
        tmp_path.resolve() / "sample_logs" / "llm" / "llm_x.negative.json"
    )
    assert workspace.display(rule_path) == "rules/llm/llm_x.yml"
    assert workspace.display(Path("/elsewhere/x.yml")) == "/elsewhere/x.yml"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("title: [unclosed", "invalid YAML"),
        ("", "no Sigma rule found"),
        ("- a\n- b\n", "YAML document 1 is a list"),
        ("title: x\nlogsource: {product: windows}\n", "invalid Sigma"),
        (rule_yaml("sel:\n  a: b\ncondition: sel and"), "invalid Sigma"),
        (
            "title: F\nlogsource: {product: windows}\nfilter:\n  rules: [x]\n"
            "  selection: {User: admin}\n  condition: not selection\n",
            "no Sigma rule found",
        ),
    ],
    ids=["yaml", "empty", "list", "no-detection", "bad-condition", "filter-only"],
)
def test_parse_errors_are_readable(text: str, message: str) -> None:
    with pytest.raises(RuleLoadError, match=message):
        parse_rule(text, Path("x.yml"))


def test_at_most_one_correlation_per_file() -> None:
    correlation = (
        "---\ntitle: C{n}\nid: 7c9e6679-7425-40de-944b-e07fc1f90c0{n}\ncorrelation:\n"
        "  type: event_count\n  rules: [base]\n  group-by: [User]\n  timespan: 5m\n"
        "  condition: {{gte: 2}}\n"
    )
    text = WINDOWS_RULE + "name: base\n" + correlation.format(n=1) + correlation.format(n=2)
    with pytest.raises(RuleLoadError, match="at most one correlation"):
        parse_rule(text, Path("x.yml"))


def test_family_follows_the_logsource_product() -> None:
    assert make_rule(WINDOWS_RULE).family is Family.WINDOWS
    llm = make_rule(rule_yaml("sel:\n  llm.prompt: x\ncondition: sel", family="llm"))
    assert llm.family is Family.LLM
    assert make_rule(WINDOWS_RULE.replace("product: windows", "product: linux")).family is None


def test_unreadable_files_raise_rule_load_errors(tmp_path: Path) -> None:
    path = tmp_path / "binary.yml"
    path.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(RuleLoadError, match="cannot read"):
        load_rule(path)
