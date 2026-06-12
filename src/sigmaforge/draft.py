"""Draft a Sigma rule from a plain-English threat sentence using a LOCAL LLM.

Local-first by design: the model is reached over an OpenAI-compatible endpoint
configured by environment variables (defaulting to LM Studio on localhost). The
drafter is wrapped in a **deterministic validator** — a freshly drafted rule is
only ever accepted if it passes, in order:

    lint  ->  convert (SPL + KQL)  ->  fire-test

The fire-test both (a) confirms the rule uses only the supported evaluation
subset and (b), when a positive event can be synthesised from the rule's own
detection, confirms the rule actually fires on it. A rule that fails any stage is
rejected and never written to disk. No network call happens in tests: the model
call is injected via ``completion_fn`` and mocked.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaCompareExpression,
    SigmaNull,
    SigmaNumber,
    SigmaString,
)

from . import convert as convert_mod
from . import evaluate as evaluate_mod
from . import lint as lint_mod

DEFAULT_BASE_URL = "http://localhost:1234/v1"

_SYSTEM_PROMPT = """You are a detection engineer. Given a threat description, output \
exactly ONE Sigma rule as YAML inside a single ```yaml code block and nothing else.

Requirements:
- Include: title, a unique UUID `id`, status, description, author, level, a valid
  `logsource`, a `detection` block, and a `condition`.
- For LLM/AI application threats use `logsource: {product: llm_app, category: gateway}`
  and fields like llm.prompt, llm.completion, llm.prompt_tokens, user.id.
- For host threats use `logsource: {category: process_creation, product: windows}`
  with standard fields (Image, CommandLine, ParentImage).
- Use only these modifiers: contains, startswith, endswith, re, all, gte, lte, gt, lt.
- Keep it concise and high-signal."""

CompletionFn = Callable[[str], str]


@dataclass
class DraftResult:
    rule_yaml: str
    accepted: bool = False
    errors: list[tuple[str, str]] = field(default_factory=list)
    splunk: str | None = None
    kusto: str | None = None


# --- model call -----------------------------------------------------------


def _default_completion(threat: str) -> str:  # pragma: no cover - needs a live local server
    from openai import OpenAI

    client = OpenAI(
        base_url=os.getenv("OPENAI_BASE_URL", DEFAULT_BASE_URL),
        api_key=os.getenv("OPENAI_API_KEY") or "not-needed",
    )
    response = client.chat.completions.create(
        model=os.getenv("SIGMA_FORGE_DRAFT_MODEL", "local-model"),
        temperature=0,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": threat},
        ],
    )
    return response.choices[0].message.content or ""


def extract_yaml(text: str) -> str:
    """Pull the YAML rule out of a model response (handles ```yaml fences)."""
    fence = re.search(r"```(?:ya?ml)?\s*\n(.*?)```", text, re.DOTALL)
    return (fence.group(1) if fence else text).strip()


# --- positive-event synthesis (for the fire-test gate) --------------------


def _literal(value: SigmaString) -> str:
    return "".join(p for p in value.s if isinstance(p, str)) or "x"


def _synthesize(node: Any) -> tuple[dict[str, Any], bool]:
    """Build an event intended to satisfy ``node``; return (event, guaranteed)."""
    if isinstance(node, ConditionAND):
        event: dict[str, Any] = {}
        guaranteed = True
        for arg in node.args:
            sub, ok = _synthesize(arg)
            event.update(sub)
            guaranteed = guaranteed and ok
        return event, guaranteed
    if isinstance(node, ConditionOR):
        # Prefer a branch we can guarantee.
        best: tuple[dict[str, Any], bool] | None = None
        for arg in node.args:
            sub, ok = _synthesize(arg)
            if ok:
                return sub, True
            best = best or (sub, False)
        return best or ({}, False)
    if isinstance(node, ConditionNOT):
        # Absence is the intended candidate for NOT filters. The later fire-test
        # proves whether that candidate really satisfies the full condition.
        return {}, True
    if isinstance(node, ConditionValueExpression):
        if isinstance(node.value, SigmaString):
            return {"_keyword": _literal(node.value)}, True
        return {}, False
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _synthesize_leaf(node.field, node.value)
    return {}, False


def _synthesize_leaf(field_name: str, value: Any) -> tuple[dict[str, Any], bool]:
    if isinstance(value, SigmaString):
        return {field_name: _literal(value)}, True
    if isinstance(value, SigmaNumber):
        return {field_name: value.to_plain()}, True
    if isinstance(value, SigmaCompareExpression):
        n = float(value.number.to_plain())  # type: ignore[arg-type]
        ops = SigmaCompareExpression.CompareOperators
        picked = {
            ops.GT: n + 1,
            ops.GTE: n,
            ops.LT: n - 1,
            ops.LTE: n,
            ops.NEQ: n + 1,
        }[value.op]
        return {field_name: picked}, True
    if isinstance(value, SigmaNull):
        return {}, True  # field absent satisfies null
    # SigmaRegularExpression and anything else: produce a value but don't promise it matches.
    if hasattr(value, "s"):
        parts = "".join(p for p in value.s if isinstance(p, (str,)))  # type: ignore[union-attr]
        return {field_name: parts or "x"}, False
    return {field_name: "x"}, False


# --- validation pipeline --------------------------------------------------


def validate_rule_yaml(rule_yaml: str) -> DraftResult:
    """Run lint -> convert -> fire-test. Returns a populated DraftResult."""
    result = DraftResult(rule_yaml=rule_yaml)

    # 1) lint
    issues = lint_mod.lint_text(rule_yaml)
    if issues:
        result.errors.extend(("lint", msg) for msg in issues)
        return result

    rule = _parse_single(rule_yaml, result)
    if rule is None:
        return result

    # 2) convert
    try:
        kind = "llm" if _is_llm(rule) else "classic"
        result.splunk = convert_mod.convert_text(rule_yaml, "splunk", kind)
        result.kusto = convert_mod.convert_text(rule_yaml, "kusto", kind)
        if not result.splunk or not result.kusto:
            result.errors.append(("convert", "a backend produced empty output"))
            return result
    except convert_mod.ConversionError as exc:
        result.errors.append(("convert", str(exc)))
        return result

    # 3) fire-test (subset-evaluable + synthesized positive must fire)
    condition = rule.detection.parsed_condition[0].parse()
    synth_event, guaranteed = _synthesize(condition)
    try:
        fired = evaluate_mod.matches(rule, synth_event)
        empty_fired = evaluate_mod.matches(rule, {})
    except evaluate_mod.UnsupportedFeatureError as exc:
        result.errors.append(("fire-test", f"rule uses an unsupported construct: {exc}"))
        return result
    if guaranteed and not fired:
        result.errors.append(("fire-test", "synthesized positive event did not fire the rule"))
        return result
    if empty_fired:
        result.errors.append(("fire-test", "rule matches an empty event"))
        return result

    result.accepted = True
    return result


def _parse_single(rule_yaml: str, result: DraftResult) -> SigmaRule | None:
    try:
        rules = SigmaCollection.from_yaml(rule_yaml).rules
    except Exception as exc:
        result.errors.append(("lint", f"parse error: {exc}"))
        return None
    if len(rules) != 1 or not isinstance(rules[0], SigmaRule):
        result.errors.append(("lint", "expected exactly one Sigma rule"))
        return None
    return rules[0]


def _is_llm(rule: SigmaRule) -> bool:
    ls = rule.logsource
    return "llm" in (ls.product or "").lower() or "llm" in (ls.category or "").lower()


def draft_rule(
    threat: str,
    completion_fn: CompletionFn | None = None,
    write_path: Path | None = None,
) -> DraftResult:
    """Draft and validate a rule. ``completion_fn`` is injectable for testing."""
    fn = completion_fn or _default_completion
    raw = fn(threat)
    rule_yaml = extract_yaml(raw)
    result = validate_rule_yaml(rule_yaml)
    if result.accepted and write_path is not None:
        Path(write_path).write_text(rule_yaml + "\n", encoding="utf-8")
    return result
