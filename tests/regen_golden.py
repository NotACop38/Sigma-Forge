"""Regenerate golden SPL/KQL conversion snapshots.

Run via ``make golden`` (or ``python -m tests.regen_golden``). Each rule produces
two snapshot files under ``tests/golden/``: ``<name>.splunk.txt`` and
``<name>.kusto.txt``. ``test_convert.py`` asserts conversions still match these.
"""

from __future__ import annotations

from pathlib import Path

from sigmaforge import convert as convert_mod

GOLDEN_DIR = Path(__file__).resolve().parent / "golden"


def write_golden() -> int:
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    count = 0
    for conv in convert_mod.convert_all():
        for target in convert_mod.TARGETS:
            out = GOLDEN_DIR / f"{conv.name}.{target}.txt"
            out.write_text(conv.query(target) + "\n", encoding="utf-8")
            count += 1
    return count


if __name__ == "__main__":
    n = write_golden()
    print(f"Wrote {n} golden snapshot(s) to {GOLDEN_DIR}")
