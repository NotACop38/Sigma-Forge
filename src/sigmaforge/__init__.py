"""sigma-forge: detection-as-code for Sigma rules (lint, convert to SPL/KQL, fire-test)."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("sigma-forge")
except PackageNotFoundError:  # pragma: no cover - source tree without an installed distribution
    __version__ = "0+unknown"
