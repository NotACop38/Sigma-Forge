"""Coverage reporting: an ATT&CK Navigator layer and a static SVG coverage card.

Coverage is derived from rule tags and resolved against the pinned taxonomies
(:mod:`sigmaforge.taxonomy`), so every technique is placed under its canonical
tactics. A rule file counts as one detection: a correlation and its base rules
are credited once, under the correlation's title.

Both artifacts are rendered deterministically (sorted input, no timestamps) so
CI can fail when the committed copies drift from the rules.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from html import escape
from pathlib import Path
from typing import Any

from . import taxonomy
from .workspace import RuleFile

NAVIGATOR_VERSION = "5.3.2"
NAVIGATOR_LAYER_FORMAT = "4.5"


@dataclass(frozen=True)
class Detection:
    name: str
    title: str
    attack: frozenset[str]
    atlas: frozenset[str]
    owasp: frozenset[str]


@dataclass(frozen=True)
class Coverage:
    detections: tuple[Detection, ...]

    def _by_id(self, framework: str) -> dict[str, list[str]]:
        index: dict[str, list[str]] = {}
        for detection in self.detections:
            for identifier in getattr(detection, framework):
                index.setdefault(identifier, []).append(detection.title)
        return {k: sorted(v) for k, v in sorted(index.items())}

    @property
    def attack(self) -> dict[str, list[str]]:
        """ATT&CK technique ID -> titles of the detections that cover it."""
        return self._by_id("attack")

    @property
    def atlas(self) -> dict[str, list[str]]:
        return self._by_id("atlas")

    @property
    def owasp(self) -> dict[str, list[str]]:
        return self._by_id("owasp")


def collect(rules: Iterable[RuleFile]) -> Coverage:
    """Aggregate tags per rule file; unknown identifiers are left to lint to report."""
    attack, atlas = taxonomy.attack(), taxonomy.atlas()
    detections = []
    for rule in rules:
        found: dict[str, set[str]] = {"attack": set(), "atlas": set(), "owasp": set()}
        for sigma_rule in rule.collection.rules:
            for tag in sigma_rule.tags:
                if tag.namespace == "attack":
                    technique = taxonomy.attack_technique(tag.name)
                    if technique is not None and technique in attack.techniques:
                        found["attack"].add(technique)
                elif tag.namespace == "atlas":
                    identifier = taxonomy.atlas_id(tag.name)
                    if identifier is not None and identifier in atlas.techniques:
                        found["atlas"].add(identifier)
                elif tag.namespace == "owasp":
                    risk = taxonomy.owasp_llm_id(tag.name)
                    if risk is not None:
                        found["owasp"].add(risk)
        detections.append(
            Detection(
                rule.name,
                rule.title,
                frozenset(found["attack"]),
                frozenset(found["atlas"]),
                frozenset(found["owasp"]),
            )
        )
    return Coverage(tuple(sorted(detections, key=lambda d: d.name)))


# --- ATT&CK Navigator layer ------------------------------------------------------


def navigator_layer(coverage: Coverage) -> dict[str, Any]:
    matrix = taxonomy.attack()
    covered = coverage.attack
    techniques: list[dict[str, Any]] = [
        {
            "techniqueID": technique,
            "score": len(titles),
            "comment": "; ".join(titles),
            "enabled": True,
            "metadata": [{"name": "detections", "value": str(len(titles))}],
        }
        for technique, titles in covered.items()
    ]
    # Expand the parents of covered sub-techniques so they are visible on load.
    parents = sorted({t.split(".")[0] for t in covered if "." in t})
    techniques += [{"techniqueID": p, "showSubtechniques": True} for p in parents]
    return {
        "name": "sigma-forge coverage",
        "versions": {
            "attack": matrix.version.split(".")[0],
            "navigator": NAVIGATOR_VERSION,
            "layer": NAVIGATOR_LAYER_FORMAT,
        },
        "domain": "enterprise-attack",
        "description": (
            f"ATT&CK Enterprise v{matrix.version} techniques covered by sigma-forge "
            "detections. Score = number of detections."
        ),
        "techniques": sorted(techniques, key=lambda t: str(t["techniqueID"])),
        "gradient": {
            "colors": ["#bfeaf7ff", "#1b95c4ff"],
            "minValue": 0,
            "maxValue": max((len(v) for v in covered.values()), default=1),
        },
        "legendItems": [],
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "selectTechniquesAcrossTactics": True,
    }


def render_layer(coverage: Coverage) -> str:
    return json.dumps(navigator_layer(coverage), indent=2, ensure_ascii=False) + "\n"


# --- SVG coverage card -------------------------------------------------------------

_W = 960
_PAD = 28
_GAP = 12
_FONT = "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace"
_CHAR = 0.61  # monospace advance width, in em
_C = {
    "bg": "#0d1117",
    "panel": "#161b22",
    "border": "#30363d",
    "text": "#c9d1d9",
    "muted": "#8b949e",
    "dim": "#484f58",
    "accent": "#4cc9f0",
    "accent2": "#80ffdb",
    "cell": "#10293a",
    "cell_hot": "#13506b",
    "off": "#12161c",
}


def _chars(width: float, size: float) -> int:
    return max(1, int(width / (size * _CHAR)))


def _wrap(text: str, max_chars: int, max_lines: int) -> list[str]:
    lines: list[str] = []
    for word in text.split():
        if lines and len(lines[-1]) + 1 + len(word) <= max_chars:
            lines[-1] += f" {word}"
        else:
            lines.append(word)
    lines = [ln if len(ln) <= max_chars else ln[: max_chars - 1] + "…" for ln in lines]
    if len(lines) > max_lines:
        last = lines[max_lines - 1]
        lines = [
            *lines[: max_lines - 1],
            (last[: max_chars - 1] if len(last) >= max_chars else last) + "…",
        ]
    return lines


def _text(
    x: float,
    y: float,
    content: str,
    size: int,
    fill: str,
    weight: str = "normal",
    anchor: str = "start",
) -> str:
    return (
        f'<text x="{x:.0f}" y="{y:.0f}" font-size="{size}" fill="{fill}" '
        f'font-weight="{weight}" text-anchor="{anchor}">{escape(content)}</text>'
    )


def _mix(low: str, high: str, t: float) -> str:
    a = [int(low[i : i + 2], 16) for i in (1, 3, 5)]
    b = [int(high[i : i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x + (y - x) * t):02x}" for x, y in zip(a, b, strict=True))


def _matrix_section(
    y: float, heading: str, matrix: taxonomy.Matrix, covered: Mapping[str, list[str]]
) -> tuple[list[str], float]:
    """Tactic columns (matrix order, covered tactics only) with one cell per technique."""
    columns: dict[str, list[str]] = {}
    for technique in covered:
        for tactic in matrix.techniques[technique].tactics:
            columns.setdefault(tactic, []).append(technique)
    ordered = sorted(columns, key=matrix.tactic_order)
    out = [_text(_PAD, y + 14, heading, 13, _C["accent2"], "bold")]
    out.append(
        _text(_W - _PAD, y + 14, f"{len(covered)} techniques", 12, _C["muted"], anchor="end")
    )
    y += 30
    if not ordered:
        out.append(_text(_PAD, y + 14, "no techniques tagged", 11, _C["muted"]))
        return out, y + 28

    width = (_W - 2 * _PAD - _GAP * (len(ordered) - 1)) / len(ordered)
    most = max(len(v) for v in covered.values())
    bottom = y
    for index, tactic_key in enumerate(ordered):
        x = _PAD + index * (width + _GAP)
        column = matrix.tactic(tactic_key)
        name = column.name if column else tactic_key
        header = _wrap(name, _chars(width - 12, 11), 2)
        out.append(
            f'<rect x="{x:.1f}" y="{y:.0f}" width="{width:.1f}" height="36" rx="6" '
            f'fill="{_C["panel"]}" stroke="{_C["border"]}"/>'
        )
        for line_no, line in enumerate(header):
            out.append(_text(x + 8, y + 15 + line_no * 13, line, 11, _C["text"], "bold"))
        cell_y = y + 44
        for technique in sorted(columns[tactic_key]):
            name_lines = _wrap(matrix.display_name(technique), _chars(width - 16, 10), 4)
            height = 26 + 13 * len(name_lines)
            count = len(covered[technique])
            fill = _mix(_C["cell"], _C["cell_hot"], count / most)
            out.append(
                f'<rect x="{x:.1f}" y="{cell_y:.0f}" width="{width:.1f}" height="{height}" '
                f'rx="6" fill="{fill}" stroke="{_C["border"]}"/>'
            )
            out.append(
                f'<rect x="{x:.1f}" y="{cell_y:.0f}" width="3" height="{height}" rx="1.5" '
                f'fill="{_C["accent"]}"/>'
            )
            out.append(_text(x + 10, cell_y + 17, technique, 11, _C["accent"], "bold"))
            if count > 1:
                out.append(
                    _text(x + width - 8, cell_y + 17, f"×{count}", 10, _C["accent2"], anchor="end")
                )
            for line_no, line in enumerate(name_lines):
                out.append(_text(x + 10, cell_y + 32 + line_no * 13, line, 10, _C["text"]))
            cell_y += height + 8
        bottom = max(bottom, cell_y)
    return out, bottom + 6


def _owasp_section(y: float, covered: Mapping[str, list[str]]) -> tuple[list[str], float]:
    out = [
        _text(
            _PAD,
            y + 14,
            f"OWASP Top 10 for LLM Applications ({taxonomy.OWASP_LLM_VERSION})",
            13,
            _C["accent2"],
            "bold",
        ),
        _text(
            _W - _PAD,
            y + 14,
            f"{len(covered)} of {len(taxonomy.OWASP_LLM_TOP10)} risks",
            12,
            _C["muted"],
            anchor="end",
        ),
    ]
    y += 30
    per_row, height = 5, 52
    width = (_W - 2 * _PAD - _GAP * (per_row - 1)) / per_row
    for index, (risk, name) in enumerate(taxonomy.OWASP_LLM_TOP10.items()):
        x = _PAD + (index % per_row) * (width + _GAP)
        cell_y = y + (index // per_row) * (height + 8)
        on = risk in covered
        out.append(
            f'<rect x="{x:.1f}" y="{cell_y:.0f}" width="{width:.1f}" height="{height}" rx="6" '
            f'fill="{_C["cell_hot"] if on else _C["off"]}" stroke="{_C["border"]}"/>'
        )
        out.append(_text(x + 10, cell_y + 18, risk, 11, _C["accent"] if on else _C["dim"], "bold"))
        state = "covered" if on else "not covered"
        out.append(
            _text(
                x + width - 8,
                cell_y + 18,
                state,
                10,
                _C["accent2"] if on else _C["dim"],
                anchor="end",
            )
        )
        for line_no, line in enumerate(_wrap(name, _chars(width - 18, 10), 2)):
            out.append(
                _text(
                    x + 10, cell_y + 33 + line_no * 12, line, 10, _C["text"] if on else _C["muted"]
                )
            )
    rows = -(-len(taxonomy.OWASP_LLM_TOP10) // per_row)
    return out, y + rows * (height + 8) + 6


def render_svg(coverage: Coverage) -> str:
    attack, atlas = taxonomy.attack(), taxonomy.atlas()
    body: list[str] = [
        _text(_PAD, 44, "Detection coverage", 22, _C["text"], "bold"),
        _text(
            _PAD,
            66,
            f"{len(coverage.detections)} detections · ATT&CK Enterprise v{attack.version} · "
            f"ATLAS {atlas.version} · OWASP LLM Top 10 ({taxonomy.OWASP_LLM_VERSION})",
            12,
            _C["muted"],
        ),
    ]
    parts, y = _matrix_section(
        88, f"MITRE ATT&CK Enterprise v{attack.version}", attack, coverage.attack
    )
    body += parts
    body.append(
        f'<line x1="{_PAD}" y1="{y:.0f}" x2="{_W - _PAD}" y2="{y:.0f}" stroke="{_C["border"]}"/>'
    )
    parts, y = _matrix_section(y + 14, f"MITRE ATLAS {atlas.version}", atlas, coverage.atlas)
    body += parts
    body.append(
        f'<line x1="{_PAD}" y1="{y:.0f}" x2="{_W - _PAD}" y2="{y:.0f}" stroke="{_C["border"]}"/>'
    )
    parts, y = _owasp_section(y + 14, coverage.owasp)
    body += parts
    height = round(y + _PAD - 8)

    summary = (
        f"{len(coverage.attack)} ATT&CK techniques, {len(coverage.atlas)} ATLAS techniques, "
        f"and {len(coverage.owasp)} of {len(taxonomy.OWASP_LLM_TOP10)} OWASP LLM risks covered."
    )
    return "\n".join(
        [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{_W}" height="{height}" '
            f'viewBox="0 0 {_W} {height}" role="img" aria-labelledby="title desc" '
            f'font-family="{_FONT}">',
            '<title id="title">sigma-forge detection coverage</title>',
            f'<desc id="desc">{escape(summary)}</desc>',
            f'<rect width="{_W}" height="{height}" rx="12" fill="{_C["bg"]}"/>',
            *body,
            "</svg>",
            "",
        ]
    )


# --- files -------------------------------------------------------------------------


def artifacts(coverage: Coverage, layer_path: Path, svg_path: Path) -> dict[Path, str]:
    return {layer_path: render_layer(coverage), svg_path: render_svg(coverage)}


def write_artifacts(files: Mapping[Path, str]) -> None:
    for path, content in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def stale_artifacts(files: Mapping[Path, str]) -> list[Path]:
    """Artifacts whose committed content differs from a fresh render."""
    return [
        path
        for path, content in files.items()
        if not path.is_file() or path.read_text(encoding="utf-8") != content
    ]
