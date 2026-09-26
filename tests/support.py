"""Builders for the rules and workspaces that tests construct on the fly."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from typing import Any

from sigma.rule import SigmaRule

from sigmaforge.workspace import RuleFile, Workspace, parse_rule

REPO_ROOT = Path(__file__).resolve().parents[1]

LOGSOURCES = {
    "windows": "logsource:\n  category: process_creation\n  product: windows\n",
    "llm": "logsource:\n  product: llm_app\n  category: gateway\n",
}
DEFAULT_TAGS = {
    "windows": ["attack.execution", "attack.t1059.001"],
    "llm": ["owasp.llm01", "atlas.t0051.000"],
}


def rule_yaml(
    detection: str,
    *,
    family: str = "windows",
    title: str = "Unit Test Rule",
    rule_id: str = "7c9e6679-7425-40de-944b-e07fc1f90a01",
    tags: list[str] | None = None,
    extra: str = "",
) -> str:
    """A complete, lint-clean rule around ``detection`` (which includes ``condition``)."""
    tag_lines = "".join(f"  - {tag}\n" for tag in (tags or DEFAULT_TAGS[family]))
    body = textwrap.indent(textwrap.dedent(detection).strip(), "  ")
    return (
        f"title: {title}\n"
        f"id: {rule_id}\n"
        "status: experimental\n"
        "description: Rule built by the test suite.\n"
        "author: sigma-forge tests\n"
        "date: 2026-01-01\n"
        "references:\n"
        "  - https://attack.mitre.org/techniques/T1059/001/\n"
        f"{LOGSOURCES[family]}"
        f"detection:\n{body}\n"
        "falsepositives:\n  - None known\n"
        "level: medium\n"
        f"tags:\n{tag_lines}"
        f"{extra}"
    )


def make_rule(text: str, name: str = "unit_rule") -> RuleFile:
    return parse_rule(text, Path(f"rules/test/{name}.yml"))


def sigma_rule(detection: str, **kwargs: Any) -> SigmaRule:
    return make_rule(rule_yaml(detection, **kwargs)).rules[0]


def make_workspace(
    root: Path,
    rules: dict[str, str],
    fixtures: dict[str, list[dict[str, Any]]] | None = None,
) -> Workspace:
    """Lay out ``rules/<pack>/<name>.yml`` and ``sample_logs/<pack>/<name>.<polarity>.json``.

    Keys look like ``"classic/win_test"`` for rules and
    ``"classic/win_test.positive"`` for fixtures.
    """
    for key, text in rules.items():
        path = root / "rules" / f"{key}.yml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    for key, events in (fixtures or {}).items():
        path = root / "sample_logs" / f"{key}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(events), encoding="utf-8")
    (root / "rules").mkdir(exist_ok=True)
    return Workspace(root)


WINDOWS_RULE = rule_yaml(
    """
    selection:
      Image|endswith: '\\whoami.exe'
    condition: selection
    """,
    title="Whoami Execution",
    tags=["attack.discovery", "attack.t1033"],
)
WINDOWS_POSITIVE = [
    {"EventID": 1, "Image": "C:\\Windows\\System32\\whoami.exe", "CommandLine": "whoami /all"}
]
WINDOWS_NEGATIVE = [
    {"EventID": 1, "Image": "C:\\Windows\\System32\\hostname.exe", "CommandLine": "hostname"}
]
