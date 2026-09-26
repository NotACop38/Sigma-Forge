"""Conversion: target applicability, golden snapshots, and pipeline invariants."""

from __future__ import annotations

from importlib import resources
from pathlib import Path

import pytest
import yaml

from sigmaforge import convert, llm_schema
from sigmaforge.evaluate import RuleMatcher
from sigmaforge.workspace import Family, RuleFile, Workspace, load_rule
from tests.support import REPO_ROOT, make_rule, rule_yaml

GOLDEN_DIR = REPO_ROOT / "tests" / "golden"
RULES = [load_rule(path) for path in Workspace(REPO_ROOT).rule_paths()]
CASES = [(rule, target.id) for rule in RULES for target in convert.targets_for(rule)]


@pytest.mark.parametrize(("rule", "target"), CASES, ids=[f"{r.name}-{t}" for r, t in CASES])
def test_conversion_matches_golden(rule: RuleFile, target: str) -> None:
    golden = GOLDEN_DIR / f"{rule.name}.{target}.txt"
    assert golden.is_file(), f"missing {golden.name}; run `make golden` and review the diff"
    assert convert.convert(rule, target) == golden.read_text(encoding="utf-8").strip(), (
        f"{rule.name} [{target}] drifted from its golden; if intended, run `make golden`"
    )


def test_no_stale_goldens() -> None:
    expected = {f"{rule.name}.{target}.txt" for rule, target in CASES}
    stale = {p.name for p in GOLDEN_DIR.glob("*.txt")} - expected
    assert not stale, f"goldens without a rule/target: {sorted(stale)}; run `make golden`"


WINDOWS = make_rule(rule_yaml("sel:\n  Image|endswith: '\\cmd.exe'\ncondition: sel"))
LLM = make_rule(rule_yaml("sel:\n  llm.prompt|contains: 'x'\ncondition: sel", family="llm"))


def test_targets_by_family() -> None:
    assert [t.id for t in convert.targets_for(WINDOWS)] == ["splunk", "defender", "sentinel"]
    assert [t.id for t in convert.targets_for(LLM)] == ["splunk", "sentinel"]


def test_correlations_compile_to_splunk_only() -> None:
    burst = load_rule(REPO_ROOT / "rules/correlation/llm_prompt_injection_burst.yml")
    assert [t.id for t in convert.targets_for(burst)] == ["splunk"]
    assert "| stats count as event_count by _time user_id" in convert.convert(burst, "splunk")


def test_unsupported_logsource_has_no_targets() -> None:
    linux = make_rule(rule_yaml("sel:\n  Image: x\ncondition: sel").replace("windows", "linux"))
    assert linux.family is None
    assert convert.targets_for(linux) == []
    with pytest.raises(convert.ConversionError, match="does not apply"):
        convert.convert(linux, "splunk")


def test_inapplicable_target_is_an_error() -> None:
    with pytest.raises(convert.ConversionError, match="does not apply"):
        convert.convert(LLM, "defender")


def test_backend_errors_become_conversion_errors() -> None:
    cased = make_rule(rule_yaml("sel:\n  CommandLine|cased: 'X'\ncondition: sel"))
    with pytest.raises(convert.ConversionError, match=r"Splunk SPL: .*[Cc]ase-sensitive"):
        convert.convert(cased, "splunk")


def test_conversion_leaves_the_parsed_rule_untouched() -> None:
    """Pipelines rename fields in place; conversion must not leak that into evaluation."""
    rule = make_rule(
        rule_yaml("sel:\n  llm.prompt|contains: 'secret'\ncondition: sel", family="llm")
    )
    convert.convert_rule(rule)
    assert RuleMatcher(rule.rules[0])({"llm.prompt": "a secret"})


@pytest.mark.parametrize("rule", [r for r in RULES if r.family is Family.LLM], ids=lambda r: r.name)
def test_llm_splunk_queries_are_scoped_to_a_sourcetype(rule: RuleFile) -> None:
    query = convert.convert(rule, "splunk")
    assert query.startswith('sourcetype="llm:gateway"'), query
    assert not query.lstrip().startswith("|")


def test_llm_pipelines_map_every_schema_field() -> None:
    for name in ("llm_splunk.yml", "llm_sentinel.yml"):
        text = resources.files("sigmaforge").joinpath("pipelines", name).read_text("utf-8")
        mapping = next(
            t["mapping"] for t in yaml.safe_load(text)["transformations"] if "mapping" in t
        )
        assert set(mapping) == set(llm_schema.FIELDS) - {"timestamp"}, name


def test_pipelines_ship_inside_the_package() -> None:
    package = Path(str(resources.files("sigmaforge")))
    assert (package / "pipelines" / "llm_splunk.yml").is_file()
    assert (package / "pipelines" / "llm_sentinel.yml").is_file()
