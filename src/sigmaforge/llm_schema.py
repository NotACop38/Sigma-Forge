"""Synthetic LLM-gateway event schema: the contract for the ``llm_app`` logsource.

The schema describes a *fictional, product-agnostic* LLM gateway log event so
that the AI/LLM rules, their fixtures, and both conversion pipelines agree on
one shape. It is enforced in two places:

* lint rejects ``llm_app`` rules that reference a field outside the schema
  (a misspelled field compiles fine but never matches in production), and
* the fire-test rejects ``llm_app`` fixture events with unknown fields or
  wrongly typed values.

Fields
------
=========================  =======  ============================================
Field                      Type     Meaning
=========================  =======  ============================================
``timestamp``              string   ISO-8601 event time
``user.id``                string   pseudonymous caller identity
``app.id``                 string   calling application or tenant
``llm.model``              string   model the request targeted
``llm.prompt``             string   prompt text sent to the model
``llm.completion``         string   completion text returned by the model
``llm.prompt_tokens``      integer  prompt token count
``llm.completion_tokens``  integer  completion token count
``request.source_ip``      string   source IP address of the request
``tool.name``              string   tool/function the agent invoked
``tool.target_host``       string   host the tool call targeted
=========================  =======  ============================================
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from datetime import datetime
from typing import Any

FIELDS: Mapping[str, type] = {
    "timestamp": str,
    "user.id": str,
    "app.id": str,
    "llm.model": str,
    "llm.prompt": str,
    "llm.completion": str,
    "llm.prompt_tokens": int,
    "llm.completion_tokens": int,
    "request.source_ip": str,
    "tool.name": str,
    "tool.target_host": str,
}


def flatten(event: Mapping[str, Any], prefix: str = "") -> Iterator[tuple[str, Any]]:
    """Yield ``(dotted_field, value)`` pairs for flat or nested event shapes."""
    for key, value in event.items():
        name = f"{prefix}{key}"
        if isinstance(value, Mapping):
            yield from flatten(value, f"{name}.")
        else:
            yield name, value


def validate_event(event: Mapping[str, Any]) -> list[str]:
    """Return schema violations for one event; an empty list means it conforms."""
    problems = []
    for name, value in flatten(event):
        expected = FIELDS.get(name)
        if expected is None:
            problems.append(f"unknown field {name!r}")
        elif value is not None and (isinstance(value, bool) or not isinstance(value, expected)):
            problems.append(f"{name!r} must be {expected.__name__}, got {type(value).__name__}")
        elif name == "timestamp" and isinstance(value, str) and not _is_iso8601(value):
            problems.append(f"'timestamp' is not ISO-8601: {value!r}")
    return problems


def _is_iso8601(text: str) -> bool:
    try:
        datetime.fromisoformat(text)
    except ValueError:
        return False
    return True
