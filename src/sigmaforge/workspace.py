"""Workspace layout, rule discovery, and rule loading.

A *workspace* is a detection repository laid out as::

    rules/<pack>/<name>.yml                  Sigma rule file (one deployable detection)
    sample_logs/<pack>/<name>.positive.json  events the detection must fire on
    sample_logs/<pack>/<name>.negative.json  events the detection must stay silent on

``<pack>`` is the rule file's parent directory (``classic``, ``llm``,
``correlation``). A rule file holds either one Sigma rule, or a correlation rule
together with the base rules it references.
"""

from __future__ import annotations

import enum
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

RULE_SUFFIXES = (".yml", ".yaml")
Polarity = Literal["positive", "negative"]
POLARITIES: tuple[Polarity, ...] = ("positive", "negative")


class Family(enum.StrEnum):
    """The log family a rule targets, keyed by its ``logsource.product``."""

    WINDOWS = "windows"
    LLM = "llm_app"


class RuleLoadError(Exception):
    """A rule file could not be read, or is not valid Sigma."""


@dataclass(frozen=True)
class RuleFile:
    """A parsed rule file: the unit that is linted, converted, and fire-tested."""

    path: Path
    text: str
    collection: SigmaCollection
    family: Family | None  # None when no conversion target supports the logsource

    @property
    def name(self) -> str:
        return self.path.stem

    @property
    def rules(self) -> list[SigmaRule]:
        return [r for r in self.collection.rules if isinstance(r, SigmaRule)]

    @property
    def correlation(self) -> SigmaCorrelationRule | None:
        return next((r for r in self.collection.rules if isinstance(r, SigmaCorrelationRule)), None)

    @property
    def title(self) -> str:
        """Title of the deployable detection: the correlation's, else the rule's."""
        head = self.correlation or self.rules[0]
        return head.title or self.name


def parse_rule(text: str, path: Path) -> RuleFile:
    """Parse rule YAML, raising :class:`RuleLoadError` with a readable reason."""
    try:
        documents = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"invalid YAML: {exc}") from exc
    if not documents:
        raise RuleLoadError("no Sigma rule found")
    for index, document in enumerate(documents, start=1):
        if not isinstance(document, dict):
            raise RuleLoadError(f"YAML document {index} is a {type(document).__name__}, not a rule")
    try:
        collection = SigmaCollection.from_dicts(documents)
        for rule in collection.rules:
            if isinstance(rule, SigmaRule):  # surface condition syntax errors at load time
                for condition in rule.detection.parsed_condition:
                    condition.parse()
    except Exception as exc:  # pySigma reports malformed rules through many exception types
        raise RuleLoadError(f"invalid Sigma: {exc}") from exc
    if not any(isinstance(r, SigmaRule) for r in collection.rules):
        raise RuleLoadError("no Sigma rule found")
    if sum(isinstance(r, SigmaCorrelationRule) for r in collection.rules) > 1:
        raise RuleLoadError("a rule file may contain at most one correlation rule")
    return RuleFile(path=path, text=text, collection=collection, family=_family(collection))


def load_rule(path: Path) -> RuleFile:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RuleLoadError(f"cannot read {path}: {exc}") from exc
    return parse_rule(text, path)


def _family(collection: SigmaCollection) -> Family | None:
    products = {r.logsource.product for r in collection.rules if isinstance(r, SigmaRule)}
    product = products.pop() if len(products) == 1 else None
    try:
        return Family(product) if product else None
    except ValueError:
        return None


@dataclass(frozen=True)
class Workspace:
    """A detection repository rooted at ``root``."""

    root: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", self.root.resolve())

    @classmethod
    def discover(cls, start: Path | None = None) -> Workspace:
        """The nearest directory at or above ``start`` that contains ``rules/``."""
        here = (start or Path.cwd()).resolve()
        for candidate in (here, *here.parents):
            if (candidate / "rules").is_dir():
                return cls(candidate)
        return cls(here)

    @property
    def rules_dir(self) -> Path:
        return self.root / "rules"

    @property
    def fixtures_dir(self) -> Path:
        return self.root / "sample_logs"

    def rule_paths(self, paths: Sequence[Path] | None = None) -> list[Path]:
        """Rule files under ``paths`` (default: ``rules/``), sorted and de-duplicated.

        Discovery is deliberately syntax-agnostic: a malformed file is still
        returned, so every gate fails on it instead of silently skipping it.
        """
        if not paths and not self.rules_dir.is_dir():
            raise RuleLoadError(f"no rules/ directory in {self.root}")
        found: set[Path] = set()
        for given in paths or [self.rules_dir]:
            path = given.resolve()
            if path.is_dir():
                found.update(p for s in RULE_SUFFIXES for p in path.rglob(f"*{s}") if p.is_file())
            elif not path.exists():
                raise RuleLoadError(f"{given}: no such file or directory")
            elif path.suffix not in RULE_SUFFIXES:
                raise RuleLoadError(f"{given}: not a .yml/.yaml rule file")
            else:
                found.add(path)
        return sorted(found)

    def fixture_path(self, rule_path: Path, polarity: Polarity) -> Path:
        return self.fixtures_dir / rule_path.parent.name / f"{rule_path.stem}.{polarity}.json"

    def fixture_paths(self) -> list[Path]:
        return sorted(p for pol in POLARITIES for p in self.fixtures_dir.rglob(f"*.{pol}.json"))

    def display(self, path: Path) -> str:
        """``path`` relative to the workspace root when possible (stable across machines)."""
        try:
            return path.resolve().relative_to(self.root).as_posix()
        except ValueError:
            return str(path)
