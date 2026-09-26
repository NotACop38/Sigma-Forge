"""Lint: metadata policy, taxonomy tags, portability, schema, shape, and uniqueness."""

from __future__ import annotations

import pytest

from sigmaforge.lint import lint_rule, lint_ruleset, lint_text, re2_incompatibilities
from tests.support import WINDOWS_RULE, make_rule, rule_yaml

DETECTION = "sel:\n  Image|endswith: '\\x.exe'\ncondition: sel"


def issues_for(text: str) -> list[str]:
    return lint_text(text)


def test_the_builder_rule_is_clean() -> None:
    assert issues_for(WINDOWS_RULE) == []


@pytest.mark.parametrize("key", ["description", "author", "date", "status", "level"])
def test_required_metadata(key: str) -> None:
    text = "\n".join(line for line in WINDOWS_RULE.splitlines() if not line.startswith(f"{key}:"))
    assert any(f"missing required '{key}'" in issue for issue in issues_for(text))


def test_missing_id() -> None:
    text = "\n".join(line for line in WINDOWS_RULE.splitlines() if not line.startswith("id:"))
    assert any("missing required 'id'" in issue for issue in issues_for(text))


def test_rules_need_a_public_reference() -> None:
    text = WINDOWS_RULE.replace("https://attack.mitre.org", "http://intranet")
    assert any("public https:// reference" in issue for issue in issues_for(text))


def test_rules_need_tags() -> None:
    text = WINDOWS_RULE.split("tags:")[0]
    assert any("missing tags" in issue for issue in issues_for(text))


@pytest.mark.parametrize(
    ("tags", "message"),
    [
        (["attack.defense-evasion"], "not an ATT&CK v19.2 tactic or technique"),
        (["attack.t1099"], "not a current ATT&CK v19.2 technique"),
        (["atlas.t9999"], "not an ATLAS 2026.09 technique or tactic"),
        (["owasp.llm11"], "not an OWASP Top 10 for LLM Applications (2025) entry"),
        (["vendor.custom"], "unknown tag namespace"),
    ],
)
def test_tags_resolve_against_the_pinned_taxonomies(tags: list[str], message: str) -> None:
    issues = issues_for(rule_yaml(DETECTION, tags=tags))
    assert any(message in issue for issue in issues), issues


@pytest.mark.parametrize(
    "tags",
    [
        ["attack.stealth", "attack.t1027.010"],
        ["attack.t1053.005"],
        ["attack.g0016", "attack.s0002", "attack.execution", "attack.t1059.001"],
        ["atlas.ta0005", "atlas.t0051.000", "owasp.llm01"],
        ["tlp.clear", "detection.threat-hunting"],
    ],
)
def test_valid_tags_are_accepted(tags: list[str]) -> None:
    assert issues_for(rule_yaml(DETECTION, tags=tags)) == []


def test_tactic_tags_must_belong_to_a_tagged_technique() -> None:
    issues = issues_for(rule_yaml(DETECTION, tags=["attack.impact", "attack.t1059.001"]))
    assert any(
        "tactic 'attack.impact' belongs to none of the tagged techniques" in i for i in issues
    )
    assert any("T1059.001 is tagged without any of its tactics (execution)" in i for i in issues)


def test_keyword_detections_are_rejected() -> None:
    issues = issues_for(rule_yaml("keywords:\n  - 'mimikatz'\ncondition: keywords"))
    assert any("keyword (full-text) detections compile to invalid KQL" in i for i in issues)


def test_regexes_must_be_re2_compatible() -> None:
    issues = issues_for(rule_yaml("sel:\n  CommandLine|re: 'a(?=b)'\ncondition: sel"))
    assert any("uses a lookaround, which RE2 (KQL) rejects" in i for i in issues)


@pytest.mark.parametrize(
    ("pattern", "problems"),
    [
        (r"a(?=b)", ["a lookaround"]),
        (r"(?<!x)y", ["a lookaround"]),
        (r"(a)\1", ["a backreference"]),
        (r"(?P<n>a)(?P=n)", ["a backreference"]),
        (r"(?>ab)", ["an atomic group"]),
        (r"a++b", ["a possessive quantifier"]),
        (r"(?(1)a|b)", ["a conditional"]),
        (r"\(?=literal\)", []),
        (r"[(?=]x", []),
        (r"[]a](?=b)", ["a lookaround"]),
        (r"\\1", []),
        (r"(?i)^abc\b[0-9]{2,}", []),
    ],
)
def test_re2_incompatibility_scanner(pattern: str, problems: list[str]) -> None:
    assert re2_incompatibilities(pattern) == problems


def test_llm_rules_may_only_use_schema_fields() -> None:
    issues = issues_for(rule_yaml("sel:\n  llm.promt: x\ncondition: sel", family="llm"))
    assert any("field 'llm.promt' is not in the llm_app schema" in i for i in issues)


def test_llm_correlation_fields_must_be_in_the_schema() -> None:
    base = rule_yaml("sel:\n  llm.prompt: x\ncondition: sel", family="llm") + "name: base\n"
    correlation = (
        "---\ntitle: Burst\nid: 7c9e6679-7425-40de-944b-e07fc1f90d01\nstatus: experimental\n"
        "description: d\nauthor: a\ndate: 2026-01-01\ncorrelation:\n  type: event_count\n"
        "  rules: [base]\n  group-by: [user.name]\n  timespan: 5m\n  condition: {gte: 2}\n"
        "level: high\ntags: [owasp.llm01]\n"
    )
    issues = issues_for(base + correlation)
    assert any("correlation field 'user.name' is not in the llm_app schema" in i for i in issues)


def test_unsupported_logsource_product() -> None:
    issues = issues_for(WINDOWS_RULE.replace("product: windows", "product: linux"))
    assert any("logsource product linux is not supported" in i for i in issues)


def test_one_rule_per_file_unless_correlated() -> None:
    second = WINDOWS_RULE.replace("Whoami Execution", "Other").replace("f90a01", "f90a02")
    issues = issues_for(WINDOWS_RULE + "---\n" + second)
    assert "a rule file must contain exactly one rule" in issues


def test_base_rules_must_be_referenced_by_the_correlation() -> None:
    base = WINDOWS_RULE + "name: used\n"
    unused = (
        WINDOWS_RULE.replace("Whoami Execution", "Unused").replace("f90a01", "f90a02")
        + "name: unused\n"
    )
    correlation = (
        "---\ntitle: Burst\nid: 7c9e6679-7425-40de-944b-e07fc1f90d02\nstatus: experimental\n"
        "description: d\nauthor: a\ndate: 2026-01-01\ncorrelation:\n  type: event_count\n"
        "  rules: [used]\n  group-by: [User]\n  timespan: 5m\n  condition: {gte: 2}\n"
        "level: high\ntags: [attack.discovery, attack.t1033]\n"
    )
    issues = issues_for(base + "---\n" + unused + correlation)
    assert "base rule 'Unused' is not referenced by the correlation" in issues


def test_pysigma_validators_run() -> None:
    detection = "sel:\n  Image: 'x'\nunused:\n  Image: 'y'\ncondition: sel"
    issues = issues_for(rule_yaml(detection))
    assert any("unused" in issue.lower() or "dangling" in issue.lower() for issue in issues)


def test_parse_errors_are_reported_as_issues() -> None:
    assert lint_text("title: [unclosed")[0].startswith("invalid YAML")


def test_ruleset_ids_names_and_titles_are_unique() -> None:
    first = make_rule(WINDOWS_RULE + "name: shared\n", "first")
    second = make_rule(WINDOWS_RULE.replace("f90a01", "f90a02") + "name: shared\n", "second")
    issues = lint_ruleset([first, second])
    assert "duplicate rule name 'shared' in first, second" in issues
    assert "duplicate rule title 'Whoami Execution' in first, second" in issues
    assert not any("duplicate rule id" in issue for issue in issues)
    assert lint_ruleset([first]) == []


def test_lint_rule_accepts_parsed_rules() -> None:
    assert lint_rule(make_rule(WINDOWS_RULE)) == []
