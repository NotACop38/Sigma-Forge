"""Deterministic Sigma rule linting (shared by ``test_lint.py`` and the drafter).

Two layers:

1. **Structural** — the rule must parse via pySigma and carry the metadata a
   production detection needs: a valid UUID ``id``, ``title``, ``status``,
   ``level``, a ``logsource`` and a ``detection`` block.
2. **pySigma validators** — the curated core validator set is run. Two
   validators are intentionally excluded and replaced with our own checks:

   * ``namespace_tag`` — the AI/LLM pack tags rules with ``owasp.*`` and
     ``atlas.*`` namespaces, which are deliberate and simply not (yet) part of
     pySigma's built-in taxonomy.
   * ``attacktag`` — the ATT&CK tactic list bundled with this pySigma build is
     non-standard (it omits ``defense-evasion`` and lists entries such as
     ``stealth``), so it produces false positives on canonical tactic tags.
     We replace it with :func:`_check_attack_tags`, which validates technique
     IDs by format and tactics against the canonical enterprise ATT&CK set.
"""

from __future__ import annotations

import re
from pathlib import Path
from uuid import UUID

from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule
from sigma.validation import SigmaValidator
from sigma.validators.core import validators as _CORE_VALIDATORS

# Validator identifiers we deliberately skip (replaced by our own checks below).
_EXCLUDED_VALIDATORS = {"namespace_tag", "attacktag"}

_REQUIRED = ("title", "status", "level")

# Canonical enterprise ATT&CK tactic shortnames (hyphenated, as used by SigmaHQ
# and the ATT&CK Navigator).
_ATTACK_TACTICS = {
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
}
_TECHNIQUE_RE = re.compile(r"^t\d{4}(\.\d{3})?$", re.IGNORECASE)


def _check_attack_tags(rule: SigmaRule | SigmaCorrelationRule) -> list[str]:
    """Validate ``attack.*`` tags: techniques by ID format, tactics by name."""
    out: list[str] = []
    title = rule.title or "<untitled>"
    for tag in rule.tags or []:
        if tag.namespace != "attack":
            continue
        if _TECHNIQUE_RE.match(tag.name):
            continue
        if tag.name in _ATTACK_TACTICS:
            continue
        out.append(f"{title}: invalid ATT&CK tag 'attack.{tag.name}'")
    return out


def _curated_validator() -> SigmaValidator:
    # Built fresh per call on purpose: SigmaValidator instances carry cross-run
    # state (e.g. duplicate-id/title tracking), so a cached one reports false
    # duplicates when linting several rules in a row.
    selected = {
        cls for ident, cls in _CORE_VALIDATORS.items() if ident not in _EXCLUDED_VALIDATORS
    }
    return SigmaValidator(selected)


def lint_text(rule_yaml: str) -> list[str]:
    """Return a list of human-readable lint issues for one rule's YAML. Empty == clean."""
    issues: list[str] = []

    try:
        collection = SigmaCollection.from_yaml(rule_yaml)
    except SigmaError as exc:
        return [f"parse error: {exc}"]
    except Exception as exc:  # malformed YAML, etc.
        return [f"parse error: {exc}"]

    if not collection.rules:
        return ["no rules parsed from document"]

    for rule in collection.rules:
        title = getattr(rule, "title", None) or "<untitled>"
        # id (UUID) and title/status/level apply to both rule and correlation rules.
        if getattr(rule, "id", None) is None:
            issues.append(f"{title}: missing required 'id' (UUID)")
        else:
            try:
                UUID(str(rule.id))
            except (ValueError, AttributeError):
                issues.append(f"{title}: 'id' is not a valid UUID")
        for attr in _REQUIRED:
            if getattr(rule, attr, None) in (None, ""):
                issues.append(f"{title}: missing required '{attr}'")
        issues.extend(_check_attack_tags(rule))

        if isinstance(rule, SigmaCorrelationRule):
            if not rule.rules:
                issues.append(f"{title}: correlation references no base rules")
            continue

        if not isinstance(rule, SigmaRule):
            continue
        if not rule.logsource or (
            not rule.logsource.category
            and not rule.logsource.product
            and not rule.logsource.service
        ):
            issues.append(f"{title}: empty or missing 'logsource'")
        if not rule.detection or not rule.detection.detections:
            issues.append(f"{title}: empty or missing 'detection'")

    validator = _curated_validator()
    for finding in validator.validate_rules(
        iter(r for r in collection.rules if isinstance(r, SigmaRule))
    ):
        issues.append(str(finding.description if hasattr(finding, "description") else finding))

    return issues


def lint_file(path: Path) -> list[str]:
    return lint_text(Path(path).read_text(encoding="utf-8"))
