"""Fire-test Sigma rules against synthetic JSON events.

The rule is parsed by pySigma (``SigmaCollection.from_yaml``) and we evaluate the
*parsed* condition/detection tree — we never re-implement the YAML parser. pySigma
resolves the condition grammar (``sel and not filt``, ``1 of sel_*``,
``all of sel_*``, keywords, value lists = OR, field maps = AND) into a tree of
AND/OR/NOT/leaf expressions; this module evaluates that tree against an event.

Supported leaf semantics (documented in ``docs/sigma-subset.md``):

* field equals (plain string / number)
* ``contains`` / ``startswith`` / ``endswith`` / ``all`` (wildcard SigmaStrings)
* ``re`` (regular expression)
* ``null`` (field absent or null)
* keywords (free-text search across all event values)

Anything else (e.g. ``base64``, ``cidr``, numeric ``lt``/``gt``, ``fieldref``)
raises :class:`UnsupportedFeatureError` with a clear message rather than guessing.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
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
    SigmaRegularExpression,
    SigmaString,
    SpecialChars,
)

from .convert import REPO_ROOT, iter_rule_files


class UnsupportedFeatureError(NotImplementedError):
    """Raised when a rule uses a construct the evaluator deliberately does not support."""


# --- field resolution -----------------------------------------------------

def _resolve_field(event: dict[str, Any], field: str) -> tuple[bool, Any]:
    """Resolve a (possibly dotted) field name. Returns (present, value)."""
    if field in event:
        return True, event[field]
    node: Any = event
    for part in field.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return False, None
    return True, node


# --- SigmaString -> regex --------------------------------------------------

def _sigmastring_to_regex(value: SigmaString) -> re.Pattern[str]:
    """Build an anchored, case-insensitive regex from a SigmaString's parts."""
    out = ["^"]
    for part in value.s:
        if part is SpecialChars.WILDCARD_MULTI:
            out.append(".*")
        elif part is SpecialChars.WILDCARD_SINGLE:
            out.append(".")
        elif isinstance(part, str):
            out.append(re.escape(part))
        else:  # pragma: no cover - placeholders (%var%) are outside the supported subset
            raise UnsupportedFeatureError("placeholder expansion is not supported")
    out.append("$")
    return re.compile("".join(out), re.IGNORECASE | re.DOTALL)


# --- leaf matching ---------------------------------------------------------

def _match_value(event_value: Any, sigma_value: Any) -> bool:
    if isinstance(event_value, list):
        return any(_match_value(v, sigma_value) for v in event_value)

    if isinstance(sigma_value, SigmaNull):
        return event_value is None

    if isinstance(sigma_value, SigmaString):
        if event_value is None:
            return False
        return _sigmastring_to_regex(sigma_value).match(str(event_value)) is not None

    if isinstance(sigma_value, SigmaRegularExpression):
        if event_value is None:
            return False
        return re.search(str(sigma_value.regexp), str(event_value)) is not None

    if isinstance(sigma_value, SigmaNumber):
        try:
            return float(event_value) == float(sigma_value.to_plain())  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return False

    if isinstance(sigma_value, SigmaCompareExpression):
        try:
            left = float(event_value)
            right = float(sigma_value.number.to_plain())  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return False
        ops = SigmaCompareExpression.CompareOperators
        return {
            ops.GT: left > right,
            ops.GTE: left >= right,
            ops.LT: left < right,
            ops.LTE: left <= right,
            ops.NEQ: left != right,
        }[sigma_value.op]

    raise UnsupportedFeatureError(
        f"unsupported value type in detection: {type(sigma_value).__name__}"
    )


def _match_keyword(event: dict[str, Any], sigma_value: Any) -> bool:
    """Keyword search: match the value against any scalar value in the event."""
    if not isinstance(sigma_value, SigmaString):
        raise UnsupportedFeatureError("keyword search supports string values only")
    pattern = _sigmastring_to_regex(sigma_value)

    def _scan(node: Any) -> bool:
        if isinstance(node, dict):
            return any(_scan(v) for v in node.values())
        if isinstance(node, list):
            return any(_scan(v) for v in node)
        return node is not None and pattern.match(str(node)) is not None

    return _scan(event)


# --- recursive tree evaluation --------------------------------------------

def _eval(node: Any, event: dict[str, Any]) -> bool:
    if isinstance(node, ConditionAND):
        return all(_eval(arg, event) for arg in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval(arg, event) for arg in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        _, event_value = _resolve_field(event, node.field)
        return _match_value(event_value, node.value)
    if isinstance(node, ConditionValueExpression):
        return _match_keyword(event, node.value)
    raise UnsupportedFeatureError(
        f"unsupported condition construct: {type(node).__name__}"
    )


def matches(rule: SigmaRule, event: dict[str, Any]) -> bool:
    """Return True if ``event`` triggers ``rule``."""
    condition = rule.detection.parsed_condition[0].parse()
    return _eval(condition, event)


def load_rule(path: Path) -> SigmaRule:
    collection = SigmaCollection.from_yaml(Path(path).read_text(encoding="utf-8"))
    rule = collection.rules[0]
    if not isinstance(rule, SigmaRule):
        raise UnsupportedFeatureError(f"{path} is not a plain Sigma rule (correlation rules unsupported)")
    return rule


# --- fire-test orchestration ----------------------------------------------

@dataclass
class FireTestReport:
    name: str
    positives_total: int = 0
    positives_matched: int = 0
    negatives_total: int = 0
    negatives_clean: int = 0  # negatives that correctly did NOT match
    skipped: bool = False

    @property
    def passed(self) -> bool:
        return (
            not self.skipped
            and self.positives_matched == self.positives_total
            and self.negatives_clean == self.negatives_total
            and self.positives_total > 0
        )


def _sample_path(rule_path: Path, polarity: str) -> Path:
    rule_path = Path(rule_path)
    sub = rule_path.parent.name  # classic / llm
    return REPO_ROOT / "sample_logs" / sub / f"{rule_path.stem}.{polarity}.json"


def _load_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, list) else [data]


def fire_test(rule_path: Path) -> FireTestReport:
    rule_path = Path(rule_path)
    rule = load_rule(rule_path)
    report = FireTestReport(name=rule_path.stem)

    positives = _load_events(_sample_path(rule_path, "positive"))
    negatives = _load_events(_sample_path(rule_path, "negative"))

    if not positives and not negatives:
        report.skipped = True
        return report

    report.positives_total = len(positives)
    report.positives_matched = sum(1 for e in positives if matches(rule, e))
    report.negatives_total = len(negatives)
    report.negatives_clean = sum(1 for e in negatives if not matches(rule, e))
    return report


def fire_test_all(paths: list[Path] | None = None) -> list[FireTestReport]:
    return [fire_test(f) for f in iter_rule_files(paths)]
