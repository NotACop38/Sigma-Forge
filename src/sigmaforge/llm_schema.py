"""Synthetic LLM gateway/app event schema — the contract for the AI/LLM pack.

This describes a *fictional, product-agnostic* "LLM gateway" log event. It exists
so detections in ``rules/llm/`` and their sample logs share one stable shape. No
real product, field, or index name is used. See ``docs/sigma-subset.md`` for the
narrative version.

Field reference
---------------
=========================  ======  ======================================================
Field                      Type    Meaning
=========================  ======  ======================================================
``timestamp``              str     ISO-8601 event time.
``user.id``                str     Pseudonymous identity of the caller.
``app.id``                 str     Logical application / tenant making the request.
``llm.model``              str     Model name the request targeted.
``llm.prompt``             str     The (user/assistant) prompt text sent to the model.
``llm.completion``         str     The model's returned completion text.
``llm.prompt_tokens``      int     Token count of the prompt.
``llm.completion_tokens``  int     Token count of the completion.
``request.source_ip``      str     Source IP of the request.
``tool.name``              str     Name of a tool/function the model was allowed to call.
``tool.target_host``       str     Host a tool action targeted (for tool-use detections).
=========================  ======  ======================================================
"""

from __future__ import annotations

from typing import Any

# Canonical, dotted field names (Sigma rules reference these exactly).
FIELDS: tuple[str, ...] = (
    "timestamp",
    "user.id",
    "app.id",
    "llm.model",
    "llm.prompt",
    "llm.completion",
    "llm.prompt_tokens",
    "llm.completion_tokens",
    "request.source_ip",
    "tool.name",
    "tool.target_host",
)

# JSON-schema-style type map, used for docs and light validation.
FIELD_TYPES: dict[str, str] = {
    "timestamp": "string",
    "user.id": "string",
    "app.id": "string",
    "llm.model": "string",
    "llm.prompt": "string",
    "llm.completion": "string",
    "llm.prompt_tokens": "integer",
    "llm.completion_tokens": "integer",
    "request.source_ip": "string",
    "tool.name": "string",
    "tool.target_host": "string",
}


def sample_event(**overrides: Any) -> dict[str, Any]:
    """Return a benign baseline LLM-gateway event (nested form), with overrides applied.

    Sample logs in ``sample_logs/llm/`` are stored in *flat dotted* form (e.g.
    ``"llm.prompt"``); the evaluator resolves both flat and nested shapes.
    """
    event: dict[str, Any] = {
        "timestamp": "2026-06-03T12:00:00Z",
        "user": {"id": "user-1042"},
        "app": {"id": "support-assistant"},
        "llm": {
            "model": "forge-instruct-1",
            "prompt": "Summarize the attached release notes for me.",
            "completion": "Here is a concise summary of the release notes...",
            "prompt_tokens": 180,
            "completion_tokens": 220,
        },
        "request": {"source_ip": "203.0.113.24"},
        "tool": {"name": "doc_search", "target_host": "wiki.internal.example"},
    }
    for key, value in overrides.items():
        event[key] = value
    return event
