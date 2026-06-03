"""Regenerate golden SPL/SPL2/KQL conversion snapshots.

Run via ``make golden`` (or ``python -m tests.regen_golden``). Each rule produces
one snapshot per applicable target under ``tests/golden/``:
``<name>.<target>.txt``. ``test_convert.py`` asserts conversions still match.
"""

from __future__ import annotations

from pathlib import Path

from sigmaforge import convert as convert_mod

GOLDEN_DIR = Path(__file__).resolve().parent / "golden"


def write_golden() -> int:
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    count = 0
    # Drop stale snapshots so removed targets/rules don't linger.
    for old in GOLDEN_DIR.glob("*.txt"):
        old.unlink()
    for conv in convert_mod.convert_all():
        for target, query in conv.queries.items():
            (GOLDEN_DIR / f"{conv.name}.{target}.txt").write_text(query + "\n", encoding="utf-8")
            count += 1
    return count


if __name__ == "__main__":
    n = write_golden()
    print(f"Wrote {n} golden snapshot(s) to {GOLDEN_DIR}")
