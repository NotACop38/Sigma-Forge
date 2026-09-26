"""Render `sigma-forge check` output to docs/images/check.svg for the README.

The image is produced from a real run of the gate over this repository, so it
cannot drift into describing behaviour the CLI does not have.

    uv run python scripts/render_check_svg.py
"""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from typer.testing import CliRunner

from sigmaforge import cli

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "images" / "check.svg"


def main() -> None:
    console = Console(
        record=True, width=88, force_terminal=True, color_system="truecolor", highlight=False
    )
    cli.console = console  # render through a recording console
    result = CliRunner().invoke(cli.app, ["check", "--root", str(ROOT)])
    if result.exit_code != 0:
        raise SystemExit(f"sigma-forge check failed; fix the rules first:\n{result.output}")
    OUTPUT.write_text(console.export_svg(title="sigma-forge check"), encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
