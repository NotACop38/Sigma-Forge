"""Evaluate parsed Sigma rules and correlations against JSON events, offline.

Rules are parsed by pySigma; this module never re-implements the YAML or
condition grammar. pySigma resolves each condition (``sel and not filter``,
``1 of sel_*``, value lists, field maps) into an AND/OR/NOT tree whose leaves
pair a field with a typed value. :class:`RuleMatcher` compiles that tree once
into predicates and validates every leaf up front, so an unsupported construct
fails loudly even in a branch that short-circuit evaluation would never reach.

The supported subset and its exact semantics are specified in
``docs/sigma-subset.md``. Anything outside it raises
:class:`UnsupportedFeatureError` instead of guessing.
"""

from __future__ import annotations

import enum
import ipaddress
import math
import multiprocessing as mp
import re
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from datetime import UTC, datetime
from functools import cache
from typing import Any, NoReturn

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.correlations import (
    SigmaCorrelationCondition,
    SigmaCorrelationRule,
    SigmaCorrelationType,
)
from sigma.correlations import SigmaCorrelationConditionOperator as CorrelationOp
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)

Event = Mapping[str, Any]
Predicate = Callable[[Event], bool]
ValueTest = Callable[[Any], bool]


class UnsupportedFeatureError(NotImplementedError):
    """The rule, or its fixtures, use a construct the evaluator deliberately rejects."""


# --- field resolution --------------------------------------------------------

_MISSING: Any = object()


def resolve_field(event: Event, field: str) -> Any:
    """Look up ``field`` as a flat dotted key first, then as a nested path.

    Returns the module-private ``_MISSING`` sentinel when the field is absent;
    use :func:`is_absent` to test for it.
    """
    if field in event:
        return event[field]
    node: Any = event
    for part in field.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return _MISSING
        node = node[part]
    return node


def is_absent(value: Any) -> bool:
    return value is _MISSING


# --- regular expressions (rule-controlled, so bounded in time) -------------

REGEX_TIMEOUT_SECONDS = 0.25
# Spawn-based platforms re-import this module in the worker, which alone can take
# longer than the regex budget; the start-up handshake is timed separately.
WORKER_STARTUP_TIMEOUT_SECONDS = 15.0

_REGEX_FLAGS = {
    SigmaRegularExpressionFlag.IGNORECASE: re.IGNORECASE,
    SigmaRegularExpressionFlag.MULTILINE: re.MULTILINE,
    SigmaRegularExpressionFlag.DOTALL: re.DOTALL,
}


def _regex_worker(pattern: str, flags: int, target: str, conn: Any) -> None:
    try:
        conn.send(("ready", None))
        conn.send(("ok", re.search(pattern, target, flags) is not None))
    finally:
        conn.close()


def _abort(proc: Any, conn: Any, message: str) -> NoReturn:
    proc.terminate()
    proc.join()
    conn.close()
    raise UnsupportedFeatureError(message)


def _bounded_search(pattern: str, flags: int, target: str) -> bool:
    """``re.search`` in a disposable process, killed after REGEX_TIMEOUT_SECONDS.

    Python's ``re`` has no timeout, and a rule regex with catastrophic
    backtracking would otherwise hang the gate (e.g. on a drafted rule).
    """
    ctx = mp.get_context("fork") if "fork" in mp.get_all_start_methods() else mp.get_context()
    parent, child = ctx.Pipe(duplex=False)
    proc = ctx.Process(target=_regex_worker, args=(pattern, flags, target, child), daemon=True)
    proc.start()
    child.close()
    try:
        if not parent.poll(WORKER_STARTUP_TIMEOUT_SECONDS):
            _abort(proc, parent, "regular expression worker failed to start")
        parent.recv()
        if not parent.poll(REGEX_TIMEOUT_SECONDS):
            _abort(
                proc,
                parent,
                f"regular expression evaluation timed out after {REGEX_TIMEOUT_SECONDS:.2f}s",
            )
        _, matched = parent.recv()
    except EOFError:
        _abort(proc, parent, "regular expression worker exited unexpectedly")
    parent.close()
    proc.join()
    return bool(matched)


def _regex_test(value: SigmaRegularExpression) -> ValueTest:
    pattern = str(value.regexp.to_plain())
    # re.ASCII aligns \d, \w, \s, and \b with PCRE (Splunk) and RE2 (KQL) defaults.
    flags = re.ASCII
    for flag in value.flags:
        flags |= _REGEX_FLAGS[flag]
    try:
        re.compile(pattern, flags)
    except (re.error, ValueError) as exc:  # ValueError: e.g. (?u) conflicts with re.ASCII
        raise UnsupportedFeatureError(f"invalid regular expression {pattern!r}: {exc}") from exc
    return lambda v: _bounded_search(pattern, flags, str(v))


# --- Sigma strings -------------------------------------------------------------


@cache
def _wildcard_regex(parts: tuple[str | SpecialChars, ...], cased: bool) -> re.Pattern[str]:
    body = "".join(
        ".*"
        if part is SpecialChars.WILDCARD_MULTI
        else "."
        if part is SpecialChars.WILDCARD_SINGLE
        else re.escape(str(part))
        for part in parts
    )
    return re.compile(body, re.DOTALL if cased else re.DOTALL | re.IGNORECASE)


def _string_test(value: SigmaString, *, anchored: bool = True) -> ValueTest:
    """Case-insensitive (unless ``|cased``) wildcard match: whole value, or anywhere."""
    parts = tuple(value.s)
    if not all(isinstance(part, str | SpecialChars) for part in parts):
        raise UnsupportedFeatureError("placeholders (%name%) need a processing pipeline to expand")
    pattern = _wildcard_regex(parts, isinstance(value, SigmaCasedString))
    if anchored:
        return lambda v: pattern.fullmatch(str(v)) is not None
    return lambda v: pattern.search(str(v)) is not None


# --- scalar value tests --------------------------------------------------------


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return None if math.isnan(number) else number


def _number_test(value: SigmaNumber) -> ValueTest:
    expected = _number(value.to_plain())

    def test(v: Any) -> bool:
        actual = _number(v)
        return actual is not None and actual == expected

    return test


_COMPARATORS: dict[Any, Callable[[float, float], bool]] = {
    SigmaCompareExpression.CompareOperators.GT: lambda a, b: a > b,
    SigmaCompareExpression.CompareOperators.GTE: lambda a, b: a >= b,
    SigmaCompareExpression.CompareOperators.LT: lambda a, b: a < b,
    SigmaCompareExpression.CompareOperators.LTE: lambda a, b: a <= b,
    SigmaCompareExpression.CompareOperators.NEQ: lambda a, b: a != b,
}


def _compare_test(value: SigmaCompareExpression) -> ValueTest:
    threshold = _number(value.number.to_plain())
    compare = _COMPARATORS.get(value.op)
    if threshold is None or compare is None:
        raise UnsupportedFeatureError(f"unsupported numeric comparison: {value}")

    def test(v: Any) -> bool:
        actual = _number(v)
        return actual is not None and compare(actual, threshold)

    return test


def _bool_test(value: SigmaBool) -> ValueTest:
    expected = value.boolean

    def test(v: Any) -> bool:
        if isinstance(v, bool):
            return v is expected
        return isinstance(v, str) and v.strip().lower() == str(expected).lower()

    return test


def _cidr_test(value: SigmaCIDRExpression) -> ValueTest:
    network = value.network

    def test(v: Any) -> bool:
        try:
            return ipaddress.ip_address(str(v).strip()) in network
        except ValueError:
            return False

    return test


def _scalar_test(value: Any) -> ValueTest:
    if isinstance(value, SigmaString):  # includes SigmaCasedString
        return _string_test(value)
    if isinstance(value, SigmaRegularExpression):
        return _regex_test(value)
    if isinstance(value, SigmaCompareExpression):
        return _compare_test(value)
    if isinstance(value, SigmaNumber):
        return _number_test(value)
    if isinstance(value, SigmaBool):
        return _bool_test(value)
    if isinstance(value, SigmaCIDRExpression):
        return _cidr_test(value)
    if isinstance(value, SigmaExpansion):  # windash, base64offset: any expanded value
        tests = [_scalar_test(v) for v in value.values]
        return lambda v: any(t(v) for t in tests)
    raise UnsupportedFeatureError(f"unsupported value type in detection: {type(value).__name__}")


# --- condition tree compilation ----------------------------------------------


def _has_value(value: Any) -> bool:
    if is_absent(value) or value is None:
        return False
    return not (isinstance(value, str | list | dict) and len(value) == 0)


def _is_null(value: Any) -> bool:
    return value is None or is_absent(value)


def _field_predicate(field: str, value: Any) -> Predicate:
    if isinstance(value, SigmaNull):
        return lambda e: _is_null(resolve_field(e, field))
    if isinstance(value, SigmaExists):
        expected = value.exists
        return lambda e: _has_value(resolve_field(e, field)) is expected
    test = _scalar_test(value)

    def predicate(event: Event) -> bool:
        actual = resolve_field(event, field)
        if _is_null(actual):
            return False
        if isinstance(actual, list):
            return any(item is not None and test(item) for item in actual)
        return test(actual)

    return predicate


def _scalars(node: Any) -> Iterator[Any]:
    if isinstance(node, Mapping):
        for child in node.values():
            yield from _scalars(child)
    elif isinstance(node, list):
        for child in node:
            yield from _scalars(child)
    elif node is not None:
        yield node


def _keyword_predicate(value: Any) -> Predicate:
    """Keywords are a full-text search: an unanchored match against any scalar value."""
    values = value.values if isinstance(value, SigmaExpansion) else [value]
    strings = [v for v in values if isinstance(v, SigmaString)]
    if len(strings) != len(values):
        raise UnsupportedFeatureError("keyword detections support string values only")
    tests = [_string_test(v, anchored=False) for v in strings]
    return lambda e: any(t(s) for s in _scalars(e) for t in tests)


def _compile(node: Any) -> Predicate:
    if isinstance(node, ConditionAND):
        parts = [_compile(arg) for arg in node.args]
        return lambda e: all(p(e) for p in parts)
    if isinstance(node, ConditionOR):
        parts = [_compile(arg) for arg in node.args]
        return lambda e: any(p(e) for p in parts)
    if isinstance(node, ConditionNOT):
        (inner,) = [_compile(arg) for arg in node.args]
        return lambda e: not inner(e)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _field_predicate(node.field, node.value)
    if isinstance(node, ConditionValueExpression):
        return _keyword_predicate(node.value)
    raise UnsupportedFeatureError(f"unsupported condition construct: {type(node).__name__}")


class RuleMatcher:
    """A Sigma rule compiled once for repeated evaluation.

    Every condition of the rule is compiled; an event matches when any
    condition holds (pySigma backends emit one query per condition).
    """

    def __init__(self, rule: SigmaRule) -> None:
        self.rule = rule
        self._conditions = [_compile(c.parse()) for c in rule.detection.parsed_condition]

    def __call__(self, event: Event) -> bool:
        return any(condition(event) for condition in self._conditions)


def matches(rule: SigmaRule, event: Event) -> bool:
    """One-off convenience wrapper around :class:`RuleMatcher`."""
    return RuleMatcher(rule)(event)


# --- correlations ----------------------------------------------------------------


class WindowModel(enum.StrEnum):
    """How a correlation ``timespan`` partitions time.

    SLIDING: any half-open interval ``[t, t + timespan)`` starting at an event.
    TUMBLING: fixed, epoch-aligned ``[k * timespan, (k + 1) * timespan)`` buckets,
    which is what the generated SPL does with ``bin _time span=<timespan>``.
    """

    SLIDING = "sliding"
    TUMBLING = "tumbling"


MAX_CORRELATION_GROUP_EVENTS = 5_000

_CORRELATION_OPS: dict[CorrelationOp, Callable[[float, float], bool]] = {
    CorrelationOp.GT: lambda a, b: a > b,
    CorrelationOp.GTE: lambda a, b: a >= b,
    CorrelationOp.LT: lambda a, b: a < b,
    CorrelationOp.LTE: lambda a, b: a <= b,
    CorrelationOp.EQ: lambda a, b: a == b,
    CorrelationOp.NEQ: lambda a, b: a != b,
}


def _correlation_value(event: Event, field: str) -> str | None:
    """A group-by or counted value as Splunk sees it: a string, or None when unset."""
    value = resolve_field(event, field)
    if _is_null(value):
        return None
    if isinstance(value, Mapping | list):
        raise UnsupportedFeatureError(f"correlation field {field!r} must hold a scalar value")
    return str(value)


def event_time(event: Event) -> float:
    """Epoch seconds of an event's ``timestamp`` (ISO-8601; naive times are UTC)."""
    raw = event.get("timestamp")
    if isinstance(raw, str):
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError:
            pass
        else:
            return (parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)).timestamp()
    raise UnsupportedFeatureError(
        f"correlation events need an ISO-8601 'timestamp' string, got {raw!r}"
    )


class CorrelationMatcher:
    """A ``event_count`` / ``value_count`` correlation compiled for evaluation."""

    def __init__(self, correlation: SigmaCorrelationRule) -> None:
        if correlation.type not in (
            SigmaCorrelationType.EVENT_COUNT,
            SigmaCorrelationType.VALUE_COUNT,
        ):
            raise UnsupportedFeatureError(f"unsupported correlation type: {correlation.type.name}")
        if len(correlation.aliases):
            raise UnsupportedFeatureError("correlation field aliases are not supported")
        condition = correlation.condition
        if not isinstance(condition, SigmaCorrelationCondition):
            raise UnsupportedFeatureError("extended correlation conditions are not supported")
        self.value_field: str | None = None
        if correlation.type is SigmaCorrelationType.VALUE_COUNT:
            if not isinstance(condition.fieldref, str):
                raise UnsupportedFeatureError("value_count correlations need a single 'field'")
            self.value_field = condition.fieldref

        bases = [ref.rule for ref in correlation.rules or []]
        if not bases or not all(isinstance(base, SigmaRule) for base in bases):
            raise UnsupportedFeatureError("correlations must reference plain Sigma rules")
        self._bases = [RuleMatcher(base) for base in bases if isinstance(base, SigmaRule)]
        self.group_by = tuple(g for g in correlation.group_by or [] if isinstance(g, str))
        self.span = float(correlation.timespan.seconds) if correlation.timespan else math.inf
        if self.span <= 0:
            raise UnsupportedFeatureError("correlation timespan must be positive")
        self._compare = _CORRELATION_OPS[condition.op]
        self.threshold = float(condition.count)

    def triggers(self, events: Iterable[Event], window: WindowModel) -> bool:
        groups: dict[tuple[str | None, ...], list[tuple[float, Event]]] = defaultdict(list)
        for event in events:
            if not any(base(event) for base in self._bases):
                continue
            key = tuple(_correlation_value(event, g) for g in self.group_by)
            # Like Splunk's `stats ... by`, events without a group-by value are dropped.
            if None in key:
                continue
            groups[key].append((event_time(event), event))

        for members in groups.values():
            if len(members) > MAX_CORRELATION_GROUP_EVENTS:
                raise UnsupportedFeatureError(
                    f"correlation group has {len(members)} events; the maximum is "
                    f"{MAX_CORRELATION_GROUP_EVENTS}"
                )
            members.sort(key=lambda item: item[0])
            measures: Iterable[float] = (
                self._tumbling(members)
                if window is WindowModel.TUMBLING
                else self._sliding(members)
            )
            if any(self._compare(measure, self.threshold) for measure in measures):
                return True
        return False

    def _value(self, event: Event) -> str | None:
        assert self.value_field is not None
        return _correlation_value(event, self.value_field)

    def _measure(self, window_events: Sequence[Event]) -> float:
        if self.value_field is None:
            return float(len(window_events))
        return float(len({v for v in map(self._value, window_events) if v is not None}))

    def _tumbling(self, members: Sequence[tuple[float, Event]]) -> list[float]:
        if math.isinf(self.span):
            return [self._measure([e for _, e in members])]
        buckets: dict[int, list[Event]] = defaultdict(list)
        for ts, event in members:
            buckets[math.floor(ts / self.span)].append(event)
        return [self._measure(bucket) for bucket in buckets.values()]

    def _sliding(self, members: Sequence[tuple[float, Event]]) -> Iterator[float]:
        """One window per start event, advanced in linear time after sorting."""
        distinct: Counter[str] = Counter()
        right = 0
        for left, (start, start_event) in enumerate(members):
            while right < len(members) and members[right][0] - start < self.span:
                if self.value_field is not None:
                    value = self._value(members[right][1])
                    if value is not None:
                        distinct[value] += 1
                right += 1
            if self.value_field is None:
                yield float(right - left)
                continue
            yield float(len(distinct))
            value = self._value(start_event)
            if value is not None:
                distinct[value] -= 1
                if distinct[value] <= 0:
                    del distinct[value]
