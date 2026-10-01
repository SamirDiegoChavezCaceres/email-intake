"""Tie it together: a raw email in, a safe structured intake record out."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from .extract import extract_fields
from .parse import parse_email
from .redact import redact
from .scan import ScanVerdict, scan_attachment


@dataclass
class IntakeResult:
    sender: str
    subject: str
    date: str
    attachments: List[ScanVerdict]
    redacted_body: str
    redactions: Dict[str, int]
    fields: Dict[str, Optional[str]]


def process_email(raw, max_attachment_bytes: int = 5 * 1024 * 1024) -> IntakeResult:
    parsed = parse_email(raw)
    verdicts = [scan_attachment(a, max_attachment_bytes) for a in parsed.attachments]
    redacted_body, redactions = redact(parsed.body)
    # Extract from the original body (not the redacted one) so masked values do
    # not hide invoice numbers, but never keep the raw PII around.
    fields = extract_fields(parsed.body)
    return IntakeResult(
        sender=parsed.sender, subject=parsed.subject, date=parsed.date,
        attachments=verdicts, redacted_body=redacted_body,
        redactions=redactions, fields=fields,
    )
