"""Redact PII from text before it is stored or forwarded.

Returns the redacted text plus a count of what was removed by type, never the
values themselves, so the audit record does not re-leak the data it masked.
"""

from __future__ import annotations

import re
from typing import Dict, Tuple

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE = re.compile(r"(?<!\d)\+?\d{0,3}[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)")
_CARD = re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)")


def _luhn(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def redact(text: str) -> Tuple[str, Dict[str, int]]:
    counts: Dict[str, int] = {}

    def sub(pattern, label, s, validate=None):
        def repl(m):
            if validate and not validate(m.group(0)):
                return m.group(0)
            counts[label] = counts.get(label, 0) + 1
            return f"[{label}]"
        return pattern.sub(repl, s)

    # Cards first (before phone, which could match card-like runs), Luhn-checked.
    text = sub(_CARD, "CARD", text, validate=_luhn)
    text = sub(_EMAIL, "EMAIL", text)
    text = sub(_PHONE, "PHONE", text)
    return text, counts
