"""Turn messy inbound email into a safe, structured intake record."""

from .extract import extract_fields
from .parse import Attachment, ParsedEmail, parse_email
from .pipeline import IntakeResult, process_email
from .redact import redact
from .scan import ScanVerdict, scan_attachment

__all__ = [
    "process_email",
    "IntakeResult",
    "parse_email",
    "ParsedEmail",
    "Attachment",
    "redact",
    "scan_attachment",
    "ScanVerdict",
    "extract_fields",
]
