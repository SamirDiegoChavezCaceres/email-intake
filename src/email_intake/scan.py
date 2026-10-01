"""Scan attachments: block dangerous types and oversize files."""

from __future__ import annotations

import os
from dataclasses import dataclass

from .parse import Attachment

BLOCKED_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".com", ".scr", ".js", ".vbs", ".ps1", ".jar", ".msi",
}
DEFAULT_MAX_BYTES = 5 * 1024 * 1024  # 5 MB


@dataclass
class ScanVerdict:
    filename: str
    ok: bool
    reason: str


def scan_attachment(att: Attachment, max_bytes: int = DEFAULT_MAX_BYTES) -> ScanVerdict:
    ext = os.path.splitext(att.filename)[1].lower()
    if ext in BLOCKED_EXTENSIONS:
        return ScanVerdict(att.filename, False, f"blocked extension {ext}")
    if att.size > max_bytes:
        return ScanVerdict(att.filename, False, f"too large ({att.size} bytes)")
    return ScanVerdict(att.filename, True, "ok")
