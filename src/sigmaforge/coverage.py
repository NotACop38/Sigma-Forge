"""ATT&CK coverage: emit a Navigator layer (v4.x JSON) and render a heatmap PNG.

Technique and tactic data are read from each rule's ``tags`` via pySigma (e.g.
``attack.t1059.001`` -> technique ``T1059.001``; ``attack.execution`` -> the
Execution tactic). ATLAS tags from the AI/LLM pack (``atlas.t0051`` ->
``AML.T0051``) are summarised separately because the ATT&CK Navigator only renders
the enterprise ATT&CK matrix.

The PNG is rendered directly with matplotlib (Agg backend) — it is NOT a
screenshot of the web Navigator.
"""

from __future__ import annotations

import json
import re
import shutil
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.colors import LinearSegmentedColormap  # noqa: E402

from .convert import iter_rule_files  # noqa: E402
from .evaluate import load_collection  # noqa: E402

_TECHNIQUE_RE = re.compile(r"^t\d{4}(\.\d{3})?$", re.IGNORECASE)
_ATLAS_RE = re.compile(r"^t\d{4}(\.\d{3})?$", re.IGNORECASE)

# ATT&CK tactic Sigma-tag shortname (hyphenated) -> (display name, matrix order).
_TACTICS = {
    "reconnaissance": ("Reconnaissance", 0),
    "resource-development": ("Resource Development", 1),
    "initial-access": ("Initial Access", 2),
    "execution": ("Execution", 3),
    "persistence": ("Persistence", 4),
    "privilege-escalation": ("Privilege Escalation", 5),
    "defense-evasion": ("Defense Evasion", 6),
    "credential-access": ("Credential Access", 7),
    "discovery": ("Discovery", 8),
    "lateral-movement": ("Lateral Movement", 9),
    "collection": ("Collection", 10),
    "command-and-control": ("Command and Control", 11),
    "exfiltration": ("Exfiltration", 12),
    "impact": ("Impact", 13),
}


@dataclass
class CoverageData:
    technique_rules: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    technique_tactics: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    atlas_rules: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))

    @property
    def attack_technique_count(self) -> int:
        return len(self.technique_rules)

    @property
    def atlas_technique_count(self) -> int:
        return len(self.atlas_rules)

    @property
    def max_count(self) -> int:
        return max((len(v) for v in self.technique_rules.values()), default=1)


def collect_coverage(paths: list[Path] | None = None) -> CoverageData:
    data = CoverageData()
    for rule_path in iter_rule_files(paths):
        for rule in load_collection(rule_path).rules:
            title = getattr(rule, "title", None) or rule_path.stem
            tactics: set[str] = set()
            techniques: set[str] = set()
            for tag in getattr(rule, "tags", []) or []:
                ns, name = tag.namespace, tag.name
                if ns == "attack" and _TECHNIQUE_RE.match(name):
                    techniques.add(name.upper())
                elif ns == "attack" and name in _TACTICS:
                    tactics.add(name)
                elif ns == "atlas" and _ATLAS_RE.match(name):
                    data.atlas_rules[f"AML.{name.upper()}"].append(title)
            for tech in techniques:
                data.technique_rules[tech].append(title)
                data.technique_tactics[tech].update(tactics)
    return data


# --- Navigator layer ------------------------------------------------------


def build_layer(data: CoverageData) -> dict:
    techniques = []
    for tech, rules in sorted(data.technique_rules.items()):
        techniques.append(
            {
                "techniqueID": tech,
                "score": len(rules),
                "comment": "; ".join(sorted(rules)),
                "enabled": True,
                "metadata": [{"name": "rules", "value": str(len(rules))}],
            }
        )
    return {
        "name": "sigma-forge — detection coverage",
        "versions": {"attack": "14", "navigator": "4.9.5", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Coverage generated from sigma-forge rule tags.",
        "techniques": techniques,
        "gradient": {
            "colors": ["#2b3a55ff", "#4cc9f0ff", "#80ffdbff"],
            "minValue": 0,
            "maxValue": max(data.max_count, 1),
        },
        "legendItems": [{"label": "covered by sigma-forge rules", "color": "#4cc9f0"}],
        "layout": {"layout": "side", "showName": True, "showID": True},
        "hideDisabled": True,
    }


# --- heatmap PNG ----------------------------------------------------------


def render_heatmap(data: CoverageData, png_path: Path) -> None:
    png_path = Path(png_path)
    png_path.parent.mkdir(parents=True, exist_ok=True)

    # Order techniques by tactic, then ID.
    def sort_key(tech: str):
        tactics = data.technique_tactics.get(tech, set())
        order = min((_TACTICS[t][1] for t in tactics if t in _TACTICS), default=99)
        return (order, tech)

    techs = sorted(data.technique_rules, key=sort_key)
    counts = [len(data.technique_rules[t]) for t in techs]
    labels = []
    for t in techs:
        tac = sorted(
            data.technique_tactics.get(t, set()), key=lambda x: _TACTICS.get(x, ("", 99))[1]
        )
        tac_name = _TACTICS[tac[0]][0] if tac else "—"
        labels.append(f"{t}  ·  {tac_name}")

    cmap = LinearSegmentedColormap.from_list("forge", ["#2b3a55", "#4cc9f0", "#80ffdb"])
    vmax = max(max(counts, default=1), 1)

    plt.rcParams.update({"font.family": "monospace"})
    fig, ax = plt.subplots(figsize=(9, max(2.4, 0.6 * len(techs) + 1.4)), dpi=160)
    fig.patch.set_facecolor("#0d1117")
    ax.set_facecolor("#0d1117")

    y = range(len(techs))
    colors = [cmap(c / vmax) for c in counts]
    ax.barh(list(y), counts, color=colors, edgecolor="#0d1117", height=0.62)
    for i, c in enumerate(counts):
        ax.text(c + 0.04, i, str(c), va="center", color="#c9d1d9", fontsize=9)

    ax.set_yticks(list(y))
    ax.set_yticklabels(labels, color="#c9d1d9", fontsize=9)
    ax.invert_yaxis()
    ax.set_xlabel("rules covering technique", color="#8b949e", fontsize=9)
    ax.set_xlim(0, vmax + 0.6)
    ax.set_xticks(range(0, vmax + 1))
    ax.tick_params(colors="#8b949e")
    for spine in ax.spines.values():
        spine.set_color("#30363d")
    ax.set_title(
        f"MITRE ATT&CK Coverage — sigma-forge  ({data.attack_technique_count} techniques)",
        color="#80ffdb",
        fontsize=12,
        pad=12,
        loc="left",
    )
    fig.tight_layout()
    fig.savefig(png_path, facecolor=fig.get_facecolor())
    plt.close(fig)


@dataclass
class CoverageSummary:
    attack_technique_count: int
    atlas_technique_count: int
    layer_path: Path
    png_path: Path


def build_coverage(
    layer_path: Path = Path("docs/attack-layer.json"),
    png_path: Path = Path("docs/images/attack-layer.png"),
    paths: list[Path] | None = None,
) -> CoverageSummary:
    data = collect_coverage(paths)
    layer_path = Path(layer_path)
    layer_path.parent.mkdir(parents=True, exist_ok=True)
    layer_path.write_text(json.dumps(build_layer(data), indent=2) + "\n", encoding="utf-8")
    render_heatmap(data, png_path)
    return CoverageSummary(
        attack_technique_count=data.attack_technique_count,
        atlas_technique_count=data.atlas_technique_count,
        layer_path=layer_path,
        png_path=Path(png_path),
    )


_SITE_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>sigma-forge — detection coverage</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ margin: 0; background: #0d1117; color: #c9d1d9;
         font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
  .wrap {{ max-width: 1000px; margin: 0 auto; padding: 2.5rem 1.25rem 4rem; }}
  h1 {{ color: #80ffdb; font-size: 2rem; margin: 0 0 .25rem; }}
  .tag {{ color: #8b949e; margin: 0 0 1.5rem; }}
  .stats {{ display: flex; gap: 1rem; flex-wrap: wrap; margin: 1.5rem 0; }}
  .stat {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px;
           padding: 1rem 1.25rem; min-width: 140px; }}
  .stat b {{ display: block; color: #4cc9f0; font-size: 1.8rem; }}
  img {{ width: 100%; border: 1px solid #30363d; border-radius: 10px; background: #0d1117; }}
  a {{ color: #4cc9f0; }}
  .links {{ margin-top: 1.5rem; }}
  footer {{ margin-top: 2.5rem; color: #6e7681; font-size: .85rem; }}
</style>
</head>
<body>
  <div class="wrap">
    <h1>sigma-forge</h1>
    <p class="tag">Detection-as-code coverage &mdash; Sigma &rarr; Splunk SPL/SPL2 &amp; Microsoft
      Sentinel/Defender KQL, fire-tested in CI.</p>
    <div class="stats">
      <div class="stat"><b>{attack}</b> ATT&amp;CK techniques</div>
      <div class="stat"><b>{atlas}</b> ATLAS techniques</div>
    </div>
    <img src="attack-layer.png" alt="MITRE ATT&CK coverage heatmap">
    <p class="links">
      &#8595; <a href="attack-layer.json">Download the ATT&amp;CK Navigator layer (v4.x JSON)</a>
      &nbsp;&bull;&nbsp; <a href="https://github.com/NotACop38/Sigma-Forge">Repository</a>
    </p>
    <footer>Generated by <code>sigma-forge coverage --site</code>. ATT&amp;CK and ATLAS are
      trademarks of The MITRE Corporation.</footer>
  </div>
</body>
</html>
"""


def _reset_generated_dir(path: Path) -> None:
    """Remove any pre-existing output path before writing generated artifacts.

    GitHub Pages uploads the complete site directory. Cleaning it first prevents
    stale committed files from being published, and unlinking symlinks prevents
    writes/uploads from following a crafted checkout entry to another directory.
    """
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=False)


def build_site(site_dir: Path, paths: list[Path] | None = None) -> CoverageSummary:
    """Build a self-contained static coverage site (index.html + heatmap PNG + layer JSON)."""
    site_dir = Path(site_dir)
    _reset_generated_dir(site_dir)
    summary = build_coverage(
        layer_path=site_dir / "attack-layer.json",
        png_path=site_dir / "attack-layer.png",
        paths=paths,
    )
    (site_dir / "index.html").write_text(
        _SITE_HTML.format(
            attack=summary.attack_technique_count, atlas=summary.atlas_technique_count
        ),
        encoding="utf-8",
    )
    return summary
