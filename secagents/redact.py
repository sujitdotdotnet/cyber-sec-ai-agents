"""Strip secrets and personal data from text before it leaves for a model or an embedding service.

Logs, code and config routinely contain credentials (``password=...``, API keys, private keys, connection strings) and
personal data (e-mail addresses, card and national-ID numbers). The analysis does not need any of those values to
reason about an attack, so they are replaced by labelled placeholders (``[REDACTED:email]``) at the one place every
model call passes through (the router). The surrounding text is kept, so the evidence still reads naturally:
``password=[REDACTED]``, ``postgresql://app:[REDACTED]@db/prod``.

IP addresses, user names and host names are NOT removed: attacker addresses and targeted accounts are the evidence.
Switch the whole thing off with ``REDACT_BEFORE_MODEL=0`` (not recommended). Patterns are conservative on purpose: a
missed secret is worse than a needlessly hidden number, but ordinary log text (timestamps, ports, CVE ids, hashes)
must survive unchanged.

Speed matters as much as accuracy: this runs on every prompt, which can be hundreds of kilobytes. Every pattern therefore
starts at a literal or at a position where a match can begin, and every repeat is bounded, so the cost grows linearly with the
text (a pattern that starts with an unbounded run, such as ``[A-Za-z0-9_.-]*password``, rescans each long token from every
position and takes minutes). ``tests/test_redact.py`` has timing guards for this.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S)
_TOKENS = [  # (label, pattern): the whole match is replaced
    ("aws-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("api-key", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
]
_BEARER = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/\-]{16,}=*")
_ASSIGNED = re.compile(  # a keyword (password, secret, token, api_key ...), up to 40 name characters, then = or : and a value of 6+ characters
    r"(?i)((?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|token)[A-Za-z0-9_.\-]{0,40}[\"']?\s*[:=]\s*)([\"']?)([^\s\"',;&]{6,})"
)
_URL_CREDENTIALS = re.compile(r"((?<![A-Za-z0-9+.\-])[a-z][a-z0-9+.\-]{0,30}://[^\s:/@]{1,100}:)[^\s@/]{1,200}(@)")
_EMAIL = re.compile(r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63}){0,8}\.[A-Za-z]{2,24}\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARD = re.compile(r"\b(?:\d[ \-]?){12,18}\d\b")


def _luhn(digits: str) -> bool:
    total, flip = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if flip:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total, flip = total + d, not flip
    return total % 10 == 0


def scrub(text: str) -> tuple[str, Counter]:
    """The text with secrets and personal data replaced, and how many of each kind were found."""
    found: Counter = Counter()
    if not text:
        return text, found

    def sub(pattern: re.Pattern, repl, label: str, s: str) -> str:
        def once(m: re.Match) -> str:
            found[label] += 1
            return repl(m) if callable(repl) else repl
        return pattern.sub(once, s)

    text = sub(_PRIVATE_KEY, "[REDACTED:private-key]", "private-key", text)
    for label, pattern in _TOKENS:
        text = sub(pattern, f"[REDACTED:{label}]", label, text)
    text = sub(_BEARER, lambda m: f"{m.group(1)}[REDACTED]", "bearer-token", text)
    def assigned(m: re.Match) -> str:
        value = m.group(3)
        if value.isdigit() and len(value) < 10:  # max_tokens=4000, token_count=123456: a number, not a secret
            return m.group(0)
        found["credential"] += 1
        return f"{m.group(1)}{m.group(2)}[REDACTED]"

    text = _ASSIGNED.sub(assigned, text)
    text = sub(_URL_CREDENTIALS, lambda m: f"{m.group(1)}[REDACTED]{m.group(2)}", "url-credential", text)
    text = sub(_EMAIL, "[REDACTED:email]", "email", text)
    text = sub(_SSN, "[REDACTED:national-id]", "national-id", text)

    def card(m: re.Match) -> str:
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn(digits):
            found["card"] += 1
            return "[REDACTED:card]"
        return m.group(0)

    return _CARD.sub(card, text), found


def scrub_value(value: Any, found: Counter) -> Any:
    """``scrub`` applied to every string inside a (nested) dict or list, e.g. a tool call's arguments."""
    if isinstance(value, str):
        clean, c = scrub(value)
        found.update(c)
        return clean
    if isinstance(value, list):
        return [scrub_value(v, found) for v in value]
    if isinstance(value, dict):
        return {k: scrub_value(v, found) for k, v in value.items()}
    return value


def scrub_messages(messages: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], Counter]:
    """A chat history with every message's text and tool-call arguments scrubbed (the input is not modified)."""
    found: Counter = Counter()
    out = []
    for m in messages:
        m2 = dict(m)
        if isinstance(m2.get("content"), str):
            m2["content"] = scrub_value(m2["content"], found)
        if m2.get("tool_calls"):
            m2["tool_calls"] = [{**c, "arguments": scrub_value(c.get("arguments", {}), found)} for c in m2["tool_calls"]]
        out.append(m2)
    return out, found
