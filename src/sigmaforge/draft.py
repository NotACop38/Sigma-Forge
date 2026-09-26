"""Draft a Sigma rule and its fixtures from a threat description with a local LLM.

The model is reached over an OpenAI-compatible ``/chat/completions`` endpoint
that defaults to a loopback address; any other host is refused unless the
caller opts in explicitly. Model output is treated as untrusted. A draft is
accepted only when it passes the same gate as a committed rule:

    format -> lint -> convert (every applicable target) -> fire-test

The fire-test runs the rule against the positive and negative events the model
supplied and also requires that an empty event does not fire, which catches
over-broad ``not filter`` conditions. When a stage fails, its errors are sent
back to the model for a bounded number of repair attempts. Nothing is written
unless a draft is accepted, and existing files are never overwritten.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import UUID, uuid4

import yaml

from . import convert, lint, llm_schema, taxonomy
from .evaluate import RuleMatcher, UnsupportedFeatureError
from .firetest import FixtureError, evaluate_fixtures, validate_events
from .workspace import Family, Polarity, RuleFile, RuleLoadError, Workspace, parse_rule

ENV_BASE_URL = "SIGMA_FORGE_LLM_BASE_URL"
ENV_MODEL = "SIGMA_FORGE_LLM_MODEL"
ENV_API_KEY = "SIGMA_FORGE_LLM_API_KEY"
DEFAULT_BASE_URL = "http://127.0.0.1:1234/v1"
DEFAULT_MODEL = "local-model"
MAX_DRAFT_EVENTS = 50

Message = dict[str, str]
CompletionFn = Callable[[list[Message]], str]


class DraftError(RuntimeError):
    """The endpoint is unreachable or misconfigured, or a draft cannot be written."""


# --- model endpoint -----------------------------------------------------------------


def is_loopback(url: str) -> bool:
    host = urlparse(url).hostname
    if host is None:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class Endpoint:
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    api_key: str | None = None
    timeout: float = 120.0

    @classmethod
    def from_env(
        cls, base_url: str | None = None, model: str | None = None, timeout: float = 120.0
    ) -> Endpoint:
        """Explicit arguments win over ``SIGMA_FORGE_LLM_*`` variables, then defaults.

        Project-specific variables are used on purpose: inheriting a global
        ``OPENAI_BASE_URL``/``OPENAI_API_KEY`` could silently send prompts to a
        cloud provider.
        """
        return cls(
            base_url=(base_url or os.environ.get(ENV_BASE_URL) or DEFAULT_BASE_URL).rstrip("/"),
            model=model or os.environ.get(ENV_MODEL) or DEFAULT_MODEL,
            api_key=os.environ.get(ENV_API_KEY) or None,
            timeout=timeout,
        )


class ChatCompletionsClient:
    """Minimal OpenAI-compatible chat client built on the standard library."""

    def __init__(self, endpoint: Endpoint, *, allow_remote: bool = False) -> None:
        scheme = urlparse(endpoint.base_url).scheme
        if scheme not in {"http", "https"}:
            raise DraftError(f"model endpoint must be an http(s) URL, got {endpoint.base_url!r}")
        self.local = is_loopback(endpoint.base_url)
        if not self.local and not allow_remote:
            raise DraftError(
                f"refusing to send the threat description to non-loopback host "
                f"{urlparse(endpoint.base_url).hostname!r}; pass --allow-remote to opt in"
            )
        self.endpoint = endpoint

    def __call__(self, messages: list[Message]) -> str:
        url = f"{self.endpoint.base_url}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.endpoint.api_key:
            headers["Authorization"] = f"Bearer {self.endpoint.api_key}"
        payload = {"model": self.endpoint.model, "temperature": 0, "messages": messages}
        request = urllib.request.Request(
            url, data=json.dumps(payload).encode(), headers=headers, method="POST"
        )
        # Loopback traffic never goes through an HTTP(S)_PROXY from the environment.
        opener = urllib.request.build_opener(
            *([urllib.request.ProxyHandler({})] if self.local else [])
        )
        try:
            with opener.open(request, timeout=self.endpoint.timeout) as response:
                body = json.load(response)
        except urllib.error.HTTPError as exc:
            detail = exc.read(300).decode("utf-8", "replace").strip()
            raise DraftError(f"model endpoint returned HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise DraftError(f"cannot reach the model endpoint at {url}: {exc.reason}") from exc
        except (TimeoutError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise DraftError(f"invalid response from the model endpoint: {exc}") from exc
        try:
            content = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise DraftError("model endpoint response has no choices[0].message.content") from exc
        if not isinstance(content, str):
            raise DraftError("model endpoint returned a non-text completion")
        return content


# --- prompt --------------------------------------------------------------------------


def system_prompt() -> str:
    tactics = ", ".join(t.key for t in taxonomy.attack().tactics)
    fields = ", ".join(llm_schema.FIELDS)
    return f"""You are a detection engineer. Write ONE Sigma rule for the threat the user \
describes, plus synthetic test events. Reply with exactly two fenced blocks and nothing else:

1. ```yaml with the Sigma rule: title, description, author, references (public https URLs
   such as attack.mitre.org, atlas.mitre.org, or genai.owasp.org pages), logsource,
   detection, falsepositives, level, and tags.
2. ```json with {{"positive": [...], "negative": [...]}}: at least two events that must
   fire the rule and at least two realistic near-miss events that must not.

Log families (pick one):
- Windows process creation: logsource {{category: process_creation, product: windows}};
  fields Image, CommandLine, ParentImage; include "EventID": 1 in every event.
  Tag MITRE ATT&CK v{taxonomy.attack().version}: at least one technique (attack.t1059.001) and
  its tactic, using these tactic names: {tactics}.
- LLM gateway: logsource {{product: llm_app, category: gateway}}; use only these fields:
  {fields}. Tag OWASP LLM Top 10 {taxonomy.OWASP_LLM_VERSION} (owasp.llm01..owasp.llm10) and
  MITRE ATLAS (atlas.t0051 for AML.T0051).

Detection constraints: modifiers contains, startswith, endswith, all, windash, re, gt, gte,
lt, lte only; no keyword lists; regular expressions must be RE2-compatible (no lookarounds
or backreferences). Events use flat dotted field names and only fictional values:
example.com domains, RFC 5737 IP addresses, no real credentials, no working payloads."""


def repair_prompt(errors: list[tuple[str, str]]) -> str:
    listed = "\n".join(f"- {stage}: {message}" for stage, message in errors)
    return (
        f"Your draft failed validation:\n{listed}\n"
        "Fix every problem and reply with the corrected rule and events in the same "
        "two-block format."
    )


# --- drafts ----------------------------------------------------------------------------


@dataclass(frozen=True)
class Draft:
    rule_yaml: str
    positive: list[dict[str, Any]]
    negative: list[dict[str, Any]]


@dataclass
class Attempt:
    response: str
    draft: Draft | None = None
    errors: list[tuple[str, str]] = field(default_factory=list)
    queries: dict[str, str] = field(default_factory=dict)
    rule: RuleFile | None = None

    @property
    def accepted(self) -> bool:
        return self.draft is not None and self.rule is not None and not self.errors


@dataclass
class DraftResult:
    attempts: list[Attempt]

    @property
    def final(self) -> Attempt:
        return self.attempts[-1]

    @property
    def accepted(self) -> bool:
        return self.final.accepted


class DraftFormatError(ValueError):
    """The model reply does not follow the two-block format."""


_FENCE = re.compile(r"```[ \t]*(\w+)?[ \t]*\r?\n(.*?)```", re.DOTALL)
_KEY_ORDER = (
    "title", "id", "name", "status", "description", "author", "date", "modified",
    "references", "logsource", "detection", "falsepositives", "level", "tags",
)  # fmt: skip


def parse_response(text: str, *, today: date, new_id: Callable[[], UUID]) -> Draft:
    blocks: dict[str, str] = {}
    for language, body in _FENCE.findall(text):
        kind = {"yaml": "yaml", "yml": "yaml", "json": "json"}.get((language or "").lower())
        if kind and kind not in blocks:
            blocks[kind] = body
    if set(blocks) != {"yaml", "json"}:
        raise DraftFormatError("expected one ```yaml rule block and one ```json events block")
    try:
        documents = [d for d in yaml.safe_load_all(blocks["yaml"]) if d is not None]
    except yaml.YAMLError as exc:
        raise DraftFormatError(f"the rule block is not valid YAML: {exc}") from exc
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise DraftFormatError("the rule block must hold exactly one Sigma rule")
    try:
        events = json.loads(blocks["json"])
    except json.JSONDecodeError as exc:
        raise DraftFormatError(f"the events block is not valid JSON: {exc}") from exc
    if not isinstance(events, dict) or set(events) != {"positive", "negative"}:
        raise DraftFormatError('the events block must be {"positive": [...], "negative": [...]}')
    for polarity in ("positive", "negative"):
        if isinstance(events[polarity], list) and len(events[polarity]) > MAX_DRAFT_EVENTS:
            raise DraftFormatError(f"at most {MAX_DRAFT_EVENTS} {polarity} events are accepted")
    return Draft(_normalize(documents[0], today, new_id), events["positive"], events["negative"])


def _normalize(rule: dict[str, Any], today: date, new_id: Callable[[], UUID]) -> str:
    """Assign a fresh id and ``status: experimental``, date it, and order keys canonically."""
    rule = {k: v for k, v in rule.items() if k != "modified"}
    rule.update(id=str(new_id()), status="experimental", date=today)
    ordered = {k: rule[k] for k in _KEY_ORDER if k in rule}
    ordered.update((k, v) for k, v in rule.items() if k not in ordered)
    return yaml.safe_dump(ordered, sort_keys=False, allow_unicode=True, width=100)


def validate(response: str, *, today: date, new_id: Callable[[], UUID]) -> Attempt:
    attempt = Attempt(response)
    try:
        attempt.draft = draft = parse_response(response, today=today, new_id=new_id)
    except DraftFormatError as exc:
        attempt.errors.append(("format", str(exc)))
        return attempt

    try:
        rule = parse_rule(draft.rule_yaml, Path("draft.yml"))
    except RuleLoadError as exc:
        attempt.errors.append(("lint", str(exc)))
        return attempt
    issues = lint.lint_rule(rule)
    if rule.correlation is not None or len(rule.rules) != 1:
        issues.append("a draft must be a single Sigma rule, not a correlation")
    attempt.errors += [("lint", issue) for issue in issues]
    if attempt.errors:
        return attempt

    for target in convert.targets_for(rule):
        try:
            attempt.queries[target.id] = convert.convert(rule, target.id)
        except convert.ConversionError as exc:
            attempt.errors.append(("convert", str(exc)))
    if attempt.errors:
        return attempt

    try:
        fixtures: dict[Polarity, list[dict[str, Any]]] = {
            "positive": validate_events(draft.positive, family=rule.family, label="positive"),
            "negative": validate_events(draft.negative, family=rule.family, label="negative"),
        }
    except FixtureError as exc:
        attempt.errors.append(("fire-test", str(exc)))
        return attempt
    result = evaluate_fixtures(rule, fixtures)
    attempt.errors += [("fire-test", failure) for failure in result.failures]
    if not attempt.errors:
        try:
            if RuleMatcher(rule.rules[0])({}):
                attempt.errors.append(("fire-test", "the rule fires on an empty event"))
        except UnsupportedFeatureError as exc:
            attempt.errors.append(("fire-test", str(exc)))
    if not attempt.errors:
        attempt.rule = rule
    return attempt


def draft_rule(
    threat: str,
    complete: CompletionFn,
    *,
    attempts: int = 3,
    today: date | None = None,
    new_id: Callable[[], UUID] = uuid4,
) -> DraftResult:
    """Ask the model for a rule, validating and requesting repairs up to ``attempts`` times."""
    if attempts < 1:
        raise ValueError("attempts must be at least 1")
    messages: list[Message] = [
        {"role": "system", "content": system_prompt()},
        {"role": "user", "content": threat},
    ]
    history: list[Attempt] = []
    for _ in range(attempts):
        response = complete(messages)
        attempt = validate(response, today=today or date.today(), new_id=new_id)
        history.append(attempt)
        if attempt.accepted:
            break
        messages += [
            {"role": "assistant", "content": response},
            {"role": "user", "content": repair_prompt(attempt.errors)},
        ]
    return DraftResult(history)


# --- writing -------------------------------------------------------------------------

_NAME = re.compile(r"[a-z0-9][a-z0-9_]{2,63}")
_PACKS = {Family.WINDOWS: ("classic", "win_"), Family.LLM: ("llm", "llm_")}


def default_name(rule: RuleFile) -> str:
    _, prefix = _PACKS[rule.family or Family.WINDOWS]
    slug = re.sub(r"[^a-z0-9]+", "_", rule.title.lower()).strip("_")
    return (slug if slug.startswith(prefix) else prefix + slug)[:64].rstrip("_")


def check_name(name: str) -> str:
    """Reject file names that are not 3-64 characters of ``[a-z0-9_]``."""
    if not _NAME.fullmatch(name):
        raise DraftError(f"invalid rule name {name!r}: use 3-64 of [a-z0-9_]")
    return name


def write_draft(attempt: Attempt, workspace: Workspace, name: str | None = None) -> list[Path]:
    """Write an accepted draft's rule and fixtures; never overwrites existing files."""
    if not attempt.accepted or attempt.draft is None or attempt.rule is None:
        raise DraftError("only an accepted draft can be written")
    name = check_name(name or default_name(attempt.rule))
    pack, _ = _PACKS[attempt.rule.family or Family.WINDOWS]
    rule_path = workspace.rules_dir / pack / f"{name}.yml"
    contents = {
        rule_path: attempt.draft.rule_yaml,
        workspace.fixture_path(rule_path, "positive"): _events_json(attempt.draft.positive),
        workspace.fixture_path(rule_path, "negative"): _events_json(attempt.draft.negative),
    }
    existing = [workspace.display(p) for p in contents if p.exists()]
    if existing:
        raise DraftError(f"refusing to overwrite {', '.join(existing)}")
    for path, text in contents.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return list(contents)


def _events_json(events: list[dict[str, Any]]) -> str:
    return json.dumps(events, indent=2, ensure_ascii=False) + "\n"
