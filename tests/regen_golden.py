"""Regenerate the golden conversion snapshots in tests/golden/.

Run with ``make golden`` after an intended conversion change, then review the
diff: goldens are the reviewable record of what each rule compiles to. Each
rule gets ``<name>.<target>.txt`` for every target that applies to it.
"""

from __future__ import annotations

from pathlib import Path

from sigmaforge.convert import convert_rule
from sigmaforge.workspace import Workspace, load_rule

GOLDEN_DIR = Path(__file__).resolve().parent / "golden"
REPO_ROOT = GOLDEN_DIR.parents[1]


def write_golden() -> int:
    GOLDEN_DIR.mkdir(exist_ok=True)
    for stale in GOLDEN_DIR.glob("*.txt"):
        stale.unlink()
    written = 0
    for path in Workspace(REPO_ROOT).rule_paths():
        rule = load_rule(path)
        for target, query in convert_rule(rule).items():
            (GOLDEN_DIR / f"{rule.name}.{target}.txt").write_text(query + "\n", encoding="utf-8")
            written += 1
    return written


if __name__ == "__main__":
    print(f"wrote {write_golden()} golden snapshots to {GOLDEN_DIR}")
