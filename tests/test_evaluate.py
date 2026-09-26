"""Evaluator semantics, one Sigma construct at a time (see docs/sigma-subset.md)."""

from __future__ import annotations

from typing import Any

import pytest

from sigmaforge import evaluate
from sigmaforge.evaluate import RuleMatcher, UnsupportedFeatureError, matches
from sigmaforge.workspace import RuleLoadError
from tests.support import make_rule, rule_yaml, sigma_rule


def fires(detection: str, event: dict[str, Any], **kwargs: Any) -> bool:
    return matches(sigma_rule(detection, **kwargs), event)


# --- strings -------------------------------------------------------------------------


def test_plain_values_match_the_whole_value_case_insensitively() -> None:
    detection = "sel:\n  Image: 'C:\\Windows\\cmd.exe'\ncondition: sel"
    assert fires(detection, {"Image": "c:\\windows\\CMD.EXE"})
    assert not fires(detection, {"Image": "C:\\Windows\\cmd.exe.bak"})


@pytest.mark.parametrize(
    ("modifier", "hit", "miss"),
    [
        ("contains", "a -enc b", "a -nc b"),
        ("startswith", "-enc payload", "x -enc"),
        ("endswith", "payload -enc", "-enc payload"),
    ],
)
def test_substring_modifiers(modifier: str, hit: str, miss: str) -> None:
    detection = f"sel:\n  CommandLine|{modifier}: '-enc'\ncondition: sel"
    assert fires(detection, {"CommandLine": hit})
    assert not fires(detection, {"CommandLine": miss})


def test_wildcards_and_escaped_wildcards() -> None:
    assert fires("sel:\n  Image: 'c?d.exe'\ncondition: sel", {"Image": "cmd.exe"})
    assert not fires("sel:\n  Image: 'c?d.exe'\ncondition: sel", {"Image": "cd.exe"})
    literal = "sel:\n  CommandLine: 'a\\*b'\ncondition: sel"
    assert fires(literal, {"CommandLine": "a*b"})
    assert not fires(literal, {"CommandLine": "axxb"})


def test_values_span_newlines() -> None:
    assert fires("sel:\n  CommandLine|contains: 'b'\ncondition: sel", {"CommandLine": "a\nb\nc"})


def test_cased_modifier_is_case_sensitive() -> None:
    detection = "sel:\n  CommandLine|cased: 'Invoke'\ncondition: sel"
    assert fires(detection, {"CommandLine": "Invoke"})
    assert not fires(detection, {"CommandLine": "invoke"})


def test_all_modifier_requires_every_value() -> None:
    detection = "sel:\n  CommandLine|contains|all: ['process', 'create']\ncondition: sel"
    assert fires(detection, {"CommandLine": "wmic process call create"})
    assert not fires(detection, {"CommandLine": "wmic process list"})


def test_windash_expands_dash_variants() -> None:
    detection = "sel:\n  CommandLine|windash|contains: ' -enc '\ncondition: sel"
    for dash in ("-", "/", "\u2013", "\u2014", "\u2015"):
        assert fires(detection, {"CommandLine": f"powershell {dash}enc AAAA"}), dash
    assert not fires(detection, {"CommandLine": "powershell +enc AAAA"})


def test_base64offset_matches_any_alignment() -> None:
    detection = "sel:\n  CommandLine|base64offset|contains: 'IEX'\ncondition: sel"
    for encoded in ("SUVY", "lFW", "JRV"):  # 'IEX' base64-encoded at offsets 0, 1, 2
        assert fires(detection, {"CommandLine": f"x{encoded}y"})
    assert not fires(detection, {"CommandLine": "SUV"})


# --- regular expressions ---------------------------------------------------------------


def test_regex_is_an_unanchored_case_sensitive_search() -> None:
    detection = "sel:\n  Message|re: 'hello-[0-9]+'\ncondition: sel"
    assert fires(detection, {"Message": "say hello-42 now"})
    assert not fires(detection, {"Message": "HELLO-42"})


@pytest.mark.parametrize(
    ("flags", "pattern", "hit"),
    [
        ("i", "hello", "HELLO"),
        ("m", "^second$", "first\nsecond"),
        ("s", "a.b", "a\nb"),
    ],
)
def test_regex_flags(flags: str, pattern: str, hit: str) -> None:
    assert fires(f"sel:\n  Message|re|{flags}: '{pattern}'\ncondition: sel", {"Message": hit})
    assert not fires(f"sel:\n  Message|re: '{pattern}'\ncondition: sel", {"Message": hit})


def test_regex_classes_are_ascii_like_pcre_and_re2() -> None:
    detection = "sel:\n  Message|re: '^\\d+$'\ncondition: sel"
    assert fires(detection, {"Message": "123"})
    assert not fires(detection, {"Message": "\u0661\u0662\u0663"})  # Arabic-Indic digits


def test_invalid_regex_is_rejected_at_load_time() -> None:
    with pytest.raises(RuleLoadError, match="invalid"):
        make_rule(rule_yaml("sel:\n  Message|re: '(unclosed'\ncondition: sel"))


def test_regex_that_conflicts_with_ascii_mode_is_rejected() -> None:
    with pytest.raises(UnsupportedFeatureError, match="invalid regular expression"):
        RuleMatcher(sigma_rule("sel:\n  Message|re: '(?u)abc'\ncondition: sel"))


def test_catastrophic_regex_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(evaluate, "REGEX_TIMEOUT_SECONDS", 0.05)
    rule = sigma_rule("sel:\n  Message|re: '^(a+)+$'\ncondition: sel")
    with pytest.raises(UnsupportedFeatureError, match="timed out"):
        matches(rule, {"Message": "a" * 40 + "!"})


# --- numbers, booleans, null, exists, cidr ---------------------------------------------


def test_numeric_equality_coerces_numeric_strings() -> None:
    detection = "sel:\n  EventID: 1\ncondition: sel"
    assert fires(detection, {"EventID": 1})
    assert fires(detection, {"EventID": "1"})
    assert not fires(detection, {"EventID": "one"})
    assert not fires(detection, {"EventID": True})


@pytest.mark.parametrize(
    ("modifier", "hit", "miss"),
    [("gt", 11, 10), ("gte", 10, 9), ("lt", 9, 10), ("lte", 10, 11)],
)
def test_numeric_comparisons(modifier: str, hit: int, miss: int) -> None:
    detection = f"sel:\n  Tokens|{modifier}: 10\ncondition: sel"
    assert fires(detection, {"Tokens": hit})
    assert fires(detection, {"Tokens": str(hit)})
    assert not fires(detection, {"Tokens": miss})
    assert not fires(detection, {"Tokens": "many"})


def test_booleans() -> None:
    detection = "sel:\n  Elevated: true\ncondition: sel"
    assert fires(detection, {"Elevated": True})
    assert fires(detection, {"Elevated": "TRUE"})
    assert not fires(detection, {"Elevated": False})
    assert not fires(detection, {"Elevated": 1})


def test_null_matches_absent_or_null_fields() -> None:
    detection = "sel:\n  ParentImage: null\ncondition: sel"
    assert fires(detection, {})
    assert fires(detection, {"ParentImage": None})
    assert not fires(detection, {"ParentImage": ""})


def test_exists_requires_a_non_empty_value() -> None:
    present = "sel:\n  User|exists: true\ncondition: sel"
    absent = "sel:\n  User|exists: false\ncondition: sel"
    for event, has_value in (
        ({"User": "alice"}, True),
        ({"User": ""}, False),
        ({"User": None}, False),
        ({"User": []}, False),
        ({}, False),
    ):
        assert fires(present, event) is has_value, event
        assert fires(absent, event) is not has_value, event


def test_cidr_membership() -> None:
    detection = "sel:\n  SourceIp|cidr: ['10.0.0.0/8', 'fd00::/8']\ncondition: sel"
    assert fires(detection, {"SourceIp": "10.20.30.40"})
    assert fires(detection, {"SourceIp": "fd00::1"})
    assert not fires(detection, {"SourceIp": "192.0.2.1"})
    assert not fires(detection, {"SourceIp": "not-an-ip"})


# --- fields and events -------------------------------------------------------------------


def test_flat_dotted_and_nested_fields_resolve_alike() -> None:
    detection = "sel:\n  llm.prompt|contains: 'secret'\ncondition: sel"
    assert fires(detection, {"llm.prompt": "a secret"}, family="llm")
    assert fires(detection, {"llm": {"prompt": "a secret"}}, family="llm")
    assert not fires(detection, {"llm": "a secret"}, family="llm")


def test_list_values_match_when_any_element_matches() -> None:
    detection = "sel:\n  Tags|contains: 'x'\ncondition: sel"
    assert fires(detection, {"Tags": ["a", None, "xyz"]})
    assert not fires(detection, {"Tags": ["a", "b"]})


def test_missing_fields_never_match_positive_tests() -> None:
    assert not fires("sel:\n  Image|contains: ''\ncondition: sel", {})


# --- conditions ----------------------------------------------------------------------------


def test_condition_grammar() -> None:
    detection = """
    sel_a:
      Image|endswith: 'a.exe'
    sel_b:
      Image|endswith: 'b.exe'
    filter:
      User: 'system'
    condition: 1 of sel_* and not filter
    """
    assert fires(detection, {"Image": "x\\a.exe", "User": "alice"})
    assert not fires(detection, {"Image": "x\\a.exe", "User": "SYSTEM"})
    assert not fires(detection, {"Image": "x\\c.exe", "User": "alice"})


def test_all_conditions_of_a_rule_are_evaluated() -> None:
    detection = "a:\n  Image: 'a'\nb:\n  Image: 'b'\ncondition:\n  - a\n  - b"
    assert fires(detection, {"Image": "b"})


def test_keywords_are_a_full_text_search() -> None:
    rule = sigma_rule("keywords:\n  - 'mimikatz'\n  - 'sekurlsa*'\ncondition: keywords")
    assert matches(rule, {"CommandLine": "run Invoke-Mimikatz now"})
    assert matches(rule, {"nested": {"deep": ["x", "sekurlsa::logonpasswords"]}})
    assert not matches(rule, {"CommandLine": "mimi katz"})


# --- refusing to guess -------------------------------------------------------------------


def test_unsupported_constructs_fail_at_compile_time_even_if_unreachable() -> None:
    detection = """
    sel:
      Image: 'x'
    ref:
      TargetUser|fieldref: SubjectUser
    condition: sel or ref
    """
    with pytest.raises(UnsupportedFeatureError, match="SigmaFieldReference"):
        RuleMatcher(sigma_rule(detection))


def test_placeholders_are_unsupported() -> None:
    detection = "sel:\n  User|expand: '%admins%'\ncondition: sel"
    with pytest.raises(UnsupportedFeatureError, match="placeholders"):
        RuleMatcher(make_rule(rule_yaml(detection)).rules[0])
