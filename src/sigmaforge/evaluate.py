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
import multiprocessing as mp
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
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
from sigma.correlations import SigmaCorrelationCondition, SigmaCorrelationRule, SigmaCorrelationType
from sigma.correlations import SigmaCorrelationConditionOperator as CorrOp
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


REGEX_TIMEOUT_SECONDS = 0.25


def _regex_search_worker(pattern: str, target: str, conn: Any) -> None:
    """Run a rule-controlled regex in a disposable child process."""
    try:
        conn.send(("ok", re.search(pattern, target) is not None))
    except re.error as exc:
        conn.send(("error", str(exc)))
    finally:
        conn.close()


def _safe_regex_search(pattern: str, target: str) -> bool:
    """Evaluate untrusted Sigma regexes with a hard timeout.

    Python's backtracking ``re`` engine can spend unbounded CPU on crafted
    patterns and near-match strings. The rule and fixture inputs in this project
    are contributor-controlled, so run the search out-of-process and kill it if
    it exceeds the small per-match budget used by CI fire tests.
    """
    ctx = mp.get_context("fork") if "fork" in mp.get_all_start_methods() else mp.get_context()
    parent_conn, child_conn = ctx.Pipe(duplex=False)
    proc = ctx.Process(target=_regex_search_worker, args=(pattern, target, child_conn))
    proc.daemon = True
    proc.start()
    child_conn.close()
    proc.join(REGEX_TIMEOUT_SECONDS)

    if proc.is_alive():
        proc.terminate()
        proc.join()
        parent_conn.close()
        raise UnsupportedFeatureError(
            f"regular expression evaluation timed out after {REGEX_TIMEOUT_SECONDS:.2f}s"
        )

    if not parent_conn.poll():
        parent_conn.close()
        raise UnsupportedFeatureError("regular expression evaluation failed")

    status, payload = parent_conn.recv()
    parent_conn.close()
    if status == "error":
        raise UnsupportedFeatureError(f"invalid regular expression: {payload}")
    return bool(payload)


def _sigma_regex_to_plain(value: SigmaRegularExpression) -> str:
    regexp = value.regexp
    to_plain = getattr(regexp, "to_plain", None)
    if callable(to_plain):
        return str(to_plain())
    return str(regexp)


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
        return _safe_regex_search(_sigma_regex_to_plain(sigma_value), str(event_value))

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
    raise UnsupportedFeatureError(f"unsupported condition construct: {type(node).__name__}")


def matches(rule: SigmaRule, event: dict[str, Any]) -> bool:
    """Return True if ``event`` triggers ``rule``."""
    condition = rule.detection.parsed_condition[0].parse()
    return _eval(condition, event)


def load_collection(path: Path) -> SigmaCollection:
    return SigmaCollection.from_yaml(Path(path).read_text(encoding="utf-8"))


def load_rule(path: Path) -> SigmaRule:
    rule = load_collection(path).rules[0]
    if not isinstance(rule, SigmaRule):
        raise UnsupportedFeatureError(
            f"{path} is not a plain Sigma rule (use correlation_triggers for correlations)"
        )
    return rule


# --- correlation evaluation ----------------------------------------------


def _parse_ts(event: dict[str, Any]) -> float:
    """Parse an event timestamp to epoch seconds (0.0 if absent/unparseable)."""
    raw = event.get("timestamp")
    if not isinstance(raw, str):
        return 0.0
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def _compare(value: float, op: CorrOp, threshold: float) -> bool:
    return {
        CorrOp.GT: value > threshold,
        CorrOp.GTE: value >= threshold,
        CorrOp.LT: value < threshold,
        CorrOp.LTE: value <= threshold,
        CorrOp.EQ: value == threshold,
        CorrOp.NEQ: value != threshold,
    }[op]


MAX_FIXTURE_EVENTS = 5_000
MAX_CORRELATION_GROUP_EVENTS = 5_000


def _check_fixture_size(events: list[dict[str, Any]], path: Path) -> None:
    """Refuse unexpectedly large synthetic fixtures before CI spends time on them."""
    if len(events) > MAX_FIXTURE_EVENTS:
        raise UnsupportedFeatureError(
            f"{path} has {len(events)} events; maximum supported fixture size is "
            f"{MAX_FIXTURE_EVENTS}"
        )


def _check_correlation_group_size(evs: list[dict[str, Any]]) -> None:
    """Bound per-group correlation work for untrusted rules and fixtures."""
    if len(evs) > MAX_CORRELATION_GROUP_EVENTS:
        raise UnsupportedFeatureError(
            f"correlation group has {len(evs)} events; maximum supported group size is "
            f"{MAX_CORRELATION_GROUP_EVENTS}"
        )


def _window_measures(
    items: list[tuple[float, dict[str, Any]]],
    span: float,
    fieldref: str | None,
):
    """Yield maximal sliding-window counts without materializing window slices.

    One maximal window is examined for each timestamp-sorted start event, matching
    the previous correlation semantics while keeping CPU and memory linear after
    sorting. For value_count correlations, a moving Counter tracks distinct field
    values incrementally instead of rebuilding a set for each overlapping window.
    """
    items = sorted(items, key=lambda x: x[0])
    counts: Counter[Any] = Counter()
    right = 0

    for left, (start_ts, start_event) in enumerate(items):
        while right < len(items) and items[right][0] - start_ts <= span:
            if fieldref is not None:
                counts[_resolve_field(items[right][1], fieldref)[1]] += 1
            right += 1

        if fieldref is None:
            yield float(right - left)
        else:
            yield float(len(counts))

            value = _resolve_field(start_event, fieldref)[1]
            counts[value] -= 1
            if counts[value] <= 0:
                del counts[value]


def correlation_triggers(collection: SigmaCollection, events: list[dict[str, Any]]) -> bool:
    """Evaluate a Sigma correlation rule (event_count / value_count) over an event set."""
    corr = next((r for r in collection.rules if isinstance(r, SigmaCorrelationRule)), None)
    if corr is None:
        raise UnsupportedFeatureError("no correlation rule found in collection")
    if corr.type not in (SigmaCorrelationType.EVENT_COUNT, SigmaCorrelationType.VALUE_COUNT):
        raise UnsupportedFeatureError(f"unsupported correlation type: {corr.type.name}")

    # Only the base rules this correlation actually references (not every rule in
    # the collection), so an unrelated rule in the same file can't trigger it.
    bases: list[SigmaRule] = []
    for ref in corr.rules or []:
        ref_rule = getattr(ref, "rule", None)
        if isinstance(ref_rule, SigmaRule):
            bases.append(ref_rule)
    if not bases:
        bases = [r for r in collection.rules if isinstance(r, SigmaRule)]
    matched = [e for e in events if any(matches(b, e) for b in bases)]

    condition = corr.condition
    if not isinstance(condition, SigmaCorrelationCondition):
        raise UnsupportedFeatureError("extended correlation conditions are not supported")

    group_by = [g for g in (corr.group_by or []) if isinstance(g, str)]
    span = float(corr.timespan.seconds) if corr.timespan else float("inf")
    op, threshold = condition.op, float(condition.count)
    fieldref = condition.fieldref

    groups: dict[tuple, list[dict[str, Any]]] = {}
    for e in matched:
        key = tuple(_resolve_field(e, g)[1] for g in group_by)
        groups.setdefault(key, []).append(e)

    if corr.type == SigmaCorrelationType.VALUE_COUNT and not isinstance(fieldref, str):
        raise UnsupportedFeatureError("value_count correlation requires a single 'field'")

    for evs in groups.values():
        _check_correlation_group_size(evs)
        timed = [(_parse_ts(e), e) for e in evs]
        value_field: str | None = (
            fieldref
            if corr.type == SigmaCorrelationType.VALUE_COUNT and isinstance(fieldref, str)
            else None
        )
        for measure in _window_measures(timed, span, value_field):
            if _compare(measure, op, threshold):
                return True
    return False


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
    sub = rule_path.parent.name  # classic / llm / correlation
    return REPO_ROOT / "sample_logs" / sub / f"{rule_path.stem}.{polarity}.json"


def _load_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    events = data if isinstance(data, list) else [data]
    _check_fixture_size(events, path)
    return events


def _is_correlation(path: Path) -> bool:
    collection = load_collection(path)
    return any(isinstance(r, SigmaCorrelationRule) for r in collection.rules)


def fire_test(rule_path: Path) -> FireTestReport:
    rule_path = Path(rule_path)
    report = FireTestReport(name=rule_path.stem)

    positives = _load_events(_sample_path(rule_path, "positive"))
    negatives = _load_events(_sample_path(rule_path, "negative"))
    if not positives and not negatives:
        report.skipped = True
        return report

    if _is_correlation(rule_path):
        # Each fixture file is ONE scenario: the positive set must trigger the
        # correlation, the negative set must not.
        collection = load_collection(rule_path)
        report.positives_total = 1
        report.positives_matched = 1 if correlation_triggers(collection, positives) else 0
        report.negatives_total = 1
        report.negatives_clean = 0 if correlation_triggers(collection, negatives) else 1
        return report

    rule = load_rule(rule_path)
    report.positives_total = len(positives)
    report.positives_matched = sum(1 for e in positives if matches(rule, e))
    report.negatives_total = len(negatives)
    report.negatives_clean = sum(1 for e in negatives if not matches(rule, e))
    return report


def fire_test_all(paths: list[Path] | None = None) -> list[FireTestReport]:
    return [fire_test(f) for f in iter_rule_files(paths)]
