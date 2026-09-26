"""Lint Sigma rules: structure, repository policy, taxonomy tags, and portability.

Checks, in the order they report:

1. **Shape**: a file holds one rule, or one correlation plus exactly the base
   rules it references.
2. **Metadata policy**: every rule carries ``id`` (a UUID), ``title``,
   ``status``, ``level``, ``description``, ``author``, ``date`` and at least one
   tag; plain rules also need a ``logsource`` and a public ``https://`` reference.
3. **Taxonomy**: ``attack.*`` tags resolve against the pinned ATT&CK snapshot
   (tactic tags must belong to a tagged technique), ``atlas.*`` against ATLAS,
   and ``owasp.*`` against the OWASP Top 10 for LLM Applications (2025).
4. **Portability**: no keyword (full-text) detections, which the Kusto backend
   compiles to invalid KQL, and no regex constructs that RE2 (KQL) rejects.
5. **Schema**: ``llm_app`` rules reference only fields of the synthetic schema.
6. **pySigma validators**: the core set, minus ``namespace_tag`` (it rejects the
   ``atlas``/``owasp`` namespaces), ``attacktag`` (replaced by check 3; it
   downloads ATT&CK at run time), ``d3_fendtag`` (downloads D3FEND), and the
   mutually exclusive ``tlpv1_tag``/``tlpv2_tag`` pair (``tlptag`` accepts both
   TLP versions).

:func:`lint_ruleset` adds the cross-file checks: ids, names, and titles must be
unique across the whole rule set.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Iterator, Sequence
from pathlib import Path

from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule, SigmaRuleBase
from sigma.types import SigmaRegularExpression
from sigma.validation import SigmaValidator
from sigma.validators.base import SigmaValidationIssue
from sigma.validators.core import validators as core_validators

from . import llm_schema, taxonomy
from .workspace import Family, RuleFile, RuleLoadError, parse_rule

EXCLUDED_VALIDATORS = frozenset(
    {"namespace_tag", "attacktag", "d3_fendtag", "tlpv1_tag", "tlpv2_tag"}
)
TAG_NAMESPACES = frozenset(
    {"attack", "atlas", "owasp", "car", "cve", "d3fend", "detection", "stp", "tlp"}
)
_REQUIRED_METADATA = ("title", "status", "level", "description", "author", "date")
_ATTACK_GROUP_OR_SOFTWARE = re.compile(r"[gs]\d{4}")


def lint_rule(rule: RuleFile) -> list[str]:
    """Return every lint issue for one parsed rule file; empty means clean."""
    issues = _shape(rule)
    for sigma_rule in rule.collection.rules:
        issues += [f"{_label(sigma_rule)}: {msg}" for msg in _metadata(sigma_rule)]
        issues += [f"{_label(sigma_rule)}: {msg}" for msg in _tags(sigma_rule)]
    for sigma_rule in rule.rules:
        issues += [f"{_label(sigma_rule)}: {msg}" for msg in _detection(sigma_rule, rule.family)]
    if rule.family is None:
        products = sorted({str(r.logsource.product) for r in rule.rules})
        issues.append(
            f"logsource product {', '.join(products)} is not supported "
            f"(expected one of: {', '.join(f.value for f in Family)})"
        )
    elif rule.family is Family.LLM and rule.correlation is not None:
        issues += _correlation_schema(rule.correlation)
    issues += _pysigma_findings(rule)
    return issues


def lint_text(text: str, path: Path = Path("draft.yml")) -> list[str]:
    """Parse and lint rule YAML (used for drafted rules that are not on disk yet)."""
    try:
        return lint_rule(parse_rule(text, path))
    except RuleLoadError as exc:
        return [str(exc)]


def lint_ruleset(rules: Sequence[RuleFile]) -> list[str]:
    """Rule ids, names, and titles must be unique across the whole rule set."""
    seen: dict[tuple[str, str], tuple[str, list[str]]] = {}
    for rule_file in rules:
        for sigma_rule in rule_file.collection.rules:
            for kind, value in (
                ("id", sigma_rule.id),
                ("name", sigma_rule.name),
                ("title", sigma_rule.title),
            ):
                if value:
                    text = str(value)
                    seen.setdefault((kind, text.casefold()), (text, []))[1].append(rule_file.name)
    return [
        f"duplicate rule {kind} {text!r} in {', '.join(files)}"
        for (kind, _), (text, files) in seen.items()
        if len(files) > 1
    ]


# --- individual checks -----------------------------------------------------------


def _label(rule: SigmaRuleBase) -> str:
    return rule.title or "<untitled>"


def _shape(rule: RuleFile) -> list[str]:
    correlation = rule.correlation
    if correlation is None:
        return [] if len(rule.rules) == 1 else ["a rule file must contain exactly one rule"]
    referenced = {id(ref.rule) for ref in correlation.rules or []}
    return [
        f"base rule {_label(r)!r} is not referenced by the correlation"
        for r in rule.rules
        if id(r) not in referenced
    ]


def _metadata(rule: SigmaRuleBase) -> list[str]:
    # pySigma already rejects an `id` that is not a UUID when it parses the rule.
    issues = [] if rule.id else ["missing required 'id' (a UUID)"]
    issues += [f"missing required '{key}'" for key in _REQUIRED_METADATA if not getattr(rule, key)]
    if not rule.tags:
        issues.append("missing tags (ATT&CK, ATLAS, or OWASP)")
    return issues


def _tags(rule: SigmaRuleBase) -> list[str]:
    attack, atlas = taxonomy.attack(), taxonomy.atlas()
    issues = []
    tactics: set[str] = set()
    techniques: set[str] = set()
    for tag in rule.tags:
        namespace, name = tag.namespace, tag.name
        if namespace not in TAG_NAMESPACES:
            issues.append(f"unknown tag namespace in '{tag}'")
        elif namespace == "attack":
            technique = taxonomy.attack_technique(name)
            if technique is not None and technique in attack.techniques:
                techniques.add(technique)
            elif technique is not None:
                issues.append(f"'{tag}' is not a current ATT&CK v{attack.version} technique")
            elif attack.tactic(name) is not None:
                tactics.add(name)
            elif not _ATTACK_GROUP_OR_SOFTWARE.fullmatch(name):
                issues.append(f"'{tag}' is not an ATT&CK v{attack.version} tactic or technique")
        elif namespace == "atlas":
            identifier = taxonomy.atlas_id(name)
            if identifier not in atlas.techniques and atlas.tactic(identifier or "") is None:
                issues.append(f"'{tag}' is not an ATLAS {atlas.version} technique or tactic")
        elif namespace == "owasp" and taxonomy.owasp_llm_id(name) is None:
            issues.append(
                f"'{tag}' is not an OWASP Top 10 for LLM Applications "
                f"({taxonomy.OWASP_LLM_VERSION}) entry"
            )

    if techniques and tactics:
        canonical = {t: set(attack.techniques[t].tactics) for t in techniques}
        issues.extend(
            f"tactic 'attack.{tactic}' belongs to none of the tagged techniques "
            f"({', '.join(sorted(techniques))})"
            for tactic in sorted(tactics - set().union(*canonical.values()))
        )
        for technique, owned in sorted(canonical.items()):
            if not owned & tactics:
                issues.append(
                    f"technique {technique} is tagged without any of its tactics "
                    f"({', '.join(sorted(owned))})"
                )
    return issues


def _detection_items(detection: SigmaDetection) -> Iterator[SigmaDetectionItem]:
    for item in detection.detection_items:
        if isinstance(item, SigmaDetection):
            yield from _detection_items(item)
        else:
            yield item


def _detection(rule: SigmaRule, family: Family | None) -> list[str]:
    issues = []
    logsource = rule.logsource
    if not logsource.product or not (logsource.category or logsource.service):
        issues.append("logsource needs a 'product' and a 'category' or 'service'")
    if not any(str(ref).startswith("https://") for ref in rule.references):
        issues.append("needs at least one public https:// reference")
    fields = set()
    for detection in rule.detection.detections.values():
        for item in _detection_items(detection):
            if item.field is None:
                issues.append("keyword (full-text) detections compile to invalid KQL")
            else:
                fields.add(item.field)
            for value in item.value:
                if isinstance(value, SigmaRegularExpression):
                    pattern = str(value.regexp.to_plain())
                    issues += [
                        f"regex {pattern!r} uses {p}, which RE2 (KQL) rejects"
                        for p in re2_incompatibilities(pattern)
                    ]
    if family is Family.LLM:
        issues += [
            f"field {f!r} is not in the llm_app schema"
            for f in sorted(fields - llm_schema.FIELDS.keys())
        ]
    return issues


def _correlation_schema(correlation: SigmaCorrelationRule) -> list[str]:
    fields = {g for g in correlation.group_by or [] if isinstance(g, str)}
    fieldref = getattr(correlation.condition, "fieldref", None)
    if isinstance(fieldref, str):
        fields.add(fieldref)
    return [
        f"{_label(correlation)}: correlation field {f!r} is not in the llm_app schema"
        for f in sorted(fields - llm_schema.FIELDS.keys())
    ]


def re2_incompatibilities(pattern: str) -> list[str]:
    """Constructs valid in PCRE/Python but rejected by RE2, which KQL uses."""
    found: set[str] = set()
    i, in_class = 0, False
    while i < len(pattern):
        char = pattern[i]
        if char == "\\":
            escaped = pattern[i + 1 : i + 2]
            if not in_class and (escaped in set("123456789") or escaped == "k"):
                found.add("a backreference")
            i += 2
            continue
        if in_class:
            in_class = char != "]"
        elif char == "[":
            in_class = True
            i += 1
            i += pattern[i : i + 1] == "^"
            i += pattern[i : i + 1] == "]"  # a leading ']' is a literal
            continue
        elif pattern.startswith(("(?=", "(?!", "(?<=", "(?<!"), i):
            found.add("a lookaround")
        elif pattern.startswith("(?>", i):
            found.add("an atomic group")
        elif pattern.startswith("(?P=", i):
            found.add("a backreference")
        elif pattern.startswith("(?(", i):
            found.add("a conditional")
        elif char in "*+?}" and pattern[i + 1 : i + 2] == "+":
            found.add("a possessive quantifier")
        i += 1
    return sorted(found)


def _pysigma_findings(rule: RuleFile) -> list[str]:
    # A fresh validator per file: pySigma validators keep cross-rule state
    # (duplicate ids/titles), which lint_ruleset handles across files instead.
    selected = {cls for key, cls in core_validators.items() if key not in EXCLUDED_VALIDATORS}
    findings = SigmaValidator(selected).validate_rules(iter(rule.rules))
    return [_describe(finding) for finding in findings]


def _describe(finding: SigmaValidationIssue) -> str:
    rules = ", ".join(_label(r) for r in finding.rules)
    details = ", ".join(
        f"{f.name}={getattr(finding, f.name)}"
        for f in dataclasses.fields(finding)
        if f.name not in {"rules", "severity"}
    )
    return f"{rules}: {finding.description}" + (f" ({details})" if details else "")
