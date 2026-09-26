"""Refresh the pinned MITRE ATT&CK and MITRE ATLAS snapshots in src/sigmaforge/data/.

This maintainer tool is the only code in the repository that talks to the
network. Nothing in the test suite or CI runs it: lint and coverage read the
committed snapshots, so tag validation stays deterministic and offline, and a
taxonomy refresh arrives as a reviewable data diff.

    uv run python scripts/update_taxonomy.py

Sources:
  * ATT&CK Enterprise: MITRE's official TAXII 2.1 server (attack-taxii.mitre.org).
  * ATLAS: the release manifest published at atlas.mitre.org/atlas-data.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import yaml

DATA_DIR = Path(__file__).resolve().parents[1] / "src" / "sigmaforge" / "data"

TAXII_ROOT = "https://attack-taxii.mitre.org/api/v21"
TAXII_ACCEPT = "application/taxii+json;version=2.1"
ENTERPRISE_COLLECTION = "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019"
ATLAS_DIST = "https://atlas.mitre.org/atlas-data/dist"

Json = dict[str, Any]


def _fetch(url: str, accept: str) -> bytes:
    request = urllib.request.Request(
        url, headers={"Accept": accept, "User-Agent": "sigma-forge/update-taxonomy"}
    )
    with urllib.request.urlopen(request, timeout=180) as response:
        return bytes(response.read())


def _taxii_objects(object_type: str) -> list[Json]:
    """Return every object of one STIX type from the Enterprise collection (all pages)."""
    base = f"{TAXII_ROOT}/collections/{ENTERPRISE_COLLECTION}/objects/"
    objects: list[Json] = []
    params = {"match[type]": object_type}
    while True:
        envelope = json.loads(_fetch(f"{base}?{urllib.parse.urlencode(params)}", TAXII_ACCEPT))
        objects.extend(envelope.get("objects", []))
        if not envelope.get("more"):
            return objects
        params["next"] = envelope["next"]


def _live(obj: Json) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def _attack_id(obj: Json) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"])
    raise ValueError(f"STIX object {obj.get('id')} has no ATT&CK external id")


def build_attack() -> Json:
    (collection,) = _taxii_objects("x-mitre-collection")
    (matrix,) = [m for m in _taxii_objects("x-mitre-matrix") if _live(m)]
    tactic_objects = {t["id"]: t for t in _taxii_objects("x-mitre-tactic") if _live(t)}
    tactics = [
        {
            "id": _attack_id(tactic_objects[ref]),
            "shortname": tactic_objects[ref]["x_mitre_shortname"],
            "name": tactic_objects[ref]["name"],
        }
        for ref in matrix["tactic_refs"]
    ]
    order = {t["shortname"]: i for i, t in enumerate(tactics)}

    techniques: dict[str, Json] = {}
    for obj in _taxii_objects("attack-pattern"):
        if not _live(obj):
            continue
        phases = {
            p["phase_name"]
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        }
        unknown = phases - order.keys()
        if unknown:
            raise ValueError(f"{_attack_id(obj)} references unknown tactics {sorted(unknown)}")
        techniques[_attack_id(obj)] = {
            "name": obj["name"],
            "tactics": sorted(phases, key=order.__getitem__),
        }

    return {
        "source": "MITRE ATT&CK Enterprise, official TAXII 2.1 server (attack-taxii.mitre.org)",
        "version": str(collection["x_mitre_version"]),
        "tactics": tactics,
        "techniques": techniques,
    }


def build_atlas() -> Json:
    manifest = yaml.safe_load(_fetch(f"{ATLAS_DIST}/manifest.yaml", "application/yaml"))
    release = max(manifest, key=lambda entry: str(entry["release-date"]))
    (path,) = [v["path"] for v in release["versions"] if str(v["format-version"]).startswith("6.")]
    data = yaml.safe_load(_fetch(f"{ATLAS_DIST}/{path}", "application/yaml"))
    relationships: dict[str, dict[str, list[Json]]] = data["relationships"]

    sequence = sorted(relationships["ATLAS-matrix"]["sequences"], key=lambda r: r["position"])
    tactics = [{"id": r["target"], "name": data["tactics"][r["target"]]["name"]} for r in sequence]
    order = {t["id"]: i for i, t in enumerate(tactics)}

    def related(source: str, kind: str) -> list[str]:
        return [str(r["target"]) for r in relationships.get(source, {}).get(kind, [])]

    techniques: dict[str, Json] = {}
    for technique_id, technique in data["techniques"].items():
        achieved = set(related(technique_id, "achieves"))
        parents = related(technique_id, "specializes")
        if not achieved and parents:  # sub-techniques inherit their parent's tactics
            achieved = set(related(parents[0], "achieves"))
        techniques[technique_id] = {
            "name": technique["name"],
            "tactics": sorted(achieved, key=order.__getitem__),
        }

    return {
        "source": "MITRE ATLAS data release (atlas.mitre.org/atlas-data)",
        "version": str(release["release"]),
        "tactics": tactics,
        "techniques": techniques,
    }


def _dump(snapshot: Json) -> str:
    """Serialize with one tactic/technique per line so refreshes diff cleanly."""

    def one_line(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False)

    lines = ["{"]
    lines += [f"  {one_line(key)}: {one_line(snapshot[key])}," for key in ("source", "version")]
    lines.append('  "tactics": [')
    tactics = snapshot["tactics"]
    lines += [
        f"    {one_line(t)}{',' if i < len(tactics) - 1 else ''}" for i, t in enumerate(tactics)
    ]
    lines.append("  ],")
    lines.append('  "techniques": {')
    items = sorted(snapshot["techniques"].items())
    lines += [
        f"    {one_line(tid)}: {one_line(entry)}{',' if i < len(items) - 1 else ''}"
        for i, (tid, entry) in enumerate(items)
    ]
    lines += ["  }", "}", ""]
    return "\n".join(lines)


def main() -> None:
    for name, build in (("attack.json", build_attack), ("atlas.json", build_atlas)):
        snapshot = build()
        (DATA_DIR / name).write_text(_dump(snapshot), encoding="utf-8")
        print(
            f"wrote {name}: version {snapshot['version']}, {len(snapshot['techniques'])} techniques"
        )


if __name__ == "__main__":
    main()
