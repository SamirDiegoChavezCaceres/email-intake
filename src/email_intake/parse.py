"""Parse a raw email (.eml) into a clean structured object."""

from __future__ import annotations

import email
import hashlib
from dataclasses import dataclass, field
from email.policy import default
from typing import List, Optional


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    data: bytes = field(repr=False, default=b"")


@dataclass
class ParsedEmail:
    sender: str
    to: str
    subject: str
    date: str
    body: str
    attachments: List[Attachment]


def parse_email(raw) -> ParsedEmail:
    msg = email.message_from_bytes(raw if isinstance(raw, bytes) else raw.encode("utf-8"),
                                   policy=default)
    body_part = msg.get_body(preferencelist=("plain", "html"))
    body = body_part.get_content().strip() if body_part else ""

    attachments: List[Attachment] = []
    for part in msg.iter_attachments():
        data = part.get_content()
        if isinstance(data, str):
            data = data.encode("utf-8", "replace")
        attachments.append(Attachment(
            filename=part.get_filename() or "unnamed",
            content_type=part.get_content_type(),
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest()[:16],
            data=data,
        ))

    def hdr(name: str) -> str:
        return str(msg[name]) if msg[name] else ""

    return ParsedEmail(
        sender=hdr("From"), to=hdr("To"), subject=hdr("Subject"),
        date=hdr("Date"), body=body, attachments=attachments,
    )
