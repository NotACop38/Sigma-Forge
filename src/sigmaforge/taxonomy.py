"""Pinned MITRE ATT&CK, MITRE ATLAS, and OWASP Top 10 for LLM Applications taxonomies.

The ATT&CK and ATLAS snapshots live in ``sigmaforge/data`` and are refreshed with
``scripts/update_taxonomy.py``. Nothing in this module touches the network, so
tag validation and coverage reports are deterministic and work offline.

Sigma tags map onto the taxonomies as follows:

==================  ==========================  =================================
Sigma tag           Canonical identifier        Resolved against
==================  ==========================  =================================
``attack.t1059.001``  ``T1059.001``             ATT&CK Enterprise techniques
``attack.execution``  tactic ``execution``      ATT&CK Enterprise tactics
``atlas.t0051.000``   ``AML.T0051.000``         ATLAS techniques
``atlas.ta0005``      ``AML.TA0005``            ATLAS tactics
``owasp.llm01``       ``LLM01``                 OWASP Top 10 for LLM Apps (2025)
==================  ==========================  =================================
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache
from importlib import resources
from typing import Any

OWASP_LLM_VERSION = "2025"
OWASP_LLM_TOP10: Mapping[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

_TECHNIQUE_TAG = re.compile(r"t\d{4}(?:\.\d{3})?")
_ATLAS_TACTIC_TAG = re.compile(r"ta\d{4}")
_OWASP_TAG = re.compile(r"llm\d{2}")


@dataclass(frozen=True)
class Tactic:
    """A matrix column. ``key`` is what techniques reference (ATT&CK shortname / ATLAS ID)."""

    id: str
    key: str
    name: str


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]  # tactic keys, in matrix order


@dataclass(frozen=True)
class Matrix:
    """One pinned taxonomy snapshot (ATT&CK Enterprise or ATLAS)."""

    name: str
    version: str
    tactics: tuple[Tactic, ...]
    techniques: Mapping[str, Technique]

    def tactic(self, key: str) -> Tactic | None:
        return next((t for t in self.tactics if t.key == key), None)

    def tactic_order(self, key: str) -> int:
        return next((i for i, t in enumerate(self.tactics) if t.key == key), len(self.tactics))

    def display_name(self, technique_id: str) -> str:
        """``Scheduled Task/Job: Scheduled Task`` for sub-techniques, else the plain name."""
        technique = self.techniques[technique_id]
        parent_id, _, suffix = technique_id.rpartition(".")
        parent = self.techniques.get(parent_id) if suffix.isdigit() else None
        return f"{parent.name}: {technique.name}" if parent else technique.name


def _load(filename: str) -> dict[str, Any]:
    text = resources.files("sigmaforge").joinpath("data", filename).read_text(encoding="utf-8")
    data: dict[str, Any] = json.loads(text)
    return data


def _techniques(raw: Mapping[str, Any]) -> dict[str, Technique]:
    return {
        tid: Technique(id=tid, name=entry["name"], tactics=tuple(entry["tactics"]))
        for tid, entry in raw.items()
    }


@cache
def attack() -> Matrix:
    """MITRE ATT&CK Enterprise; tactics are keyed by their Sigma/STIX shortname."""
    data = _load("attack.json")
    tactics = tuple(Tactic(t["id"], t["shortname"], t["name"]) for t in data["tactics"])
    return Matrix(
        "MITRE ATT&CK Enterprise", data["version"], tactics, _techniques(data["techniques"])
    )


@cache
def atlas() -> Matrix:
    """MITRE ATLAS; tactics are keyed by their ``AML.TA####`` identifier."""
    data = _load("atlas.json")
    tactics = tuple(Tactic(t["id"], t["id"], t["name"]) for t in data["tactics"])
    return Matrix("MITRE ATLAS", data["version"], tactics, _techniques(data["techniques"]))


# --- Sigma tag parsing -------------------------------------------------------


def attack_technique(tag_name: str) -> str | None:
    """``t1059.001`` -> ``T1059.001`` (format only; existence is checked by callers)."""
    return tag_name.upper() if _TECHNIQUE_TAG.fullmatch(tag_name) else None


def atlas_id(tag_name: str) -> str | None:
    """``t0051.000`` -> ``AML.T0051.000`` and ``ta0005`` -> ``AML.TA0005``."""
    if _TECHNIQUE_TAG.fullmatch(tag_name) or _ATLAS_TACTIC_TAG.fullmatch(tag_name):
        return f"AML.{tag_name.upper()}"
    return None


def owasp_llm_id(tag_name: str) -> str | None:
    """``llm01`` -> ``LLM01`` when it names an entry of the 2025 list."""
    identifier = tag_name.upper()
    return identifier if _OWASP_TAG.fullmatch(tag_name) and identifier in OWASP_LLM_TOP10 else None
