"""Pull structured intake fields out of free-text email bodies."""

from __future__ import annotations

import re
from typing import Dict, Optional

_INVOICE = re.compile(r"\b(?:invoice|order|ref(?:erence)?)\s*#?\s*([A-Z]{1,4}-?\d{3,})", re.I)
_AMOUNT = re.compile(r"(?:USD|US\$|\$)\s*([\d,]+\.\d{2})")
_DUE = re.compile(r"\bdue(?:\s*date)?\b[:\s]*([0-9]{4}-[0-9]{2}-[0-9]{2})", re.I)


def _first(pattern, text) -> Optional[str]:
    m = pattern.search(text)
    return m.group(1) if m else None


def extract_fields(text: str) -> Dict[str, Optional[str]]:
    return {
        "invoice_number": _first(_INVOICE, text),
        "amount": _first(_AMOUNT, text),
        "due_date": _first(_DUE, text),
    }
