from pathlib import Path

from email_intake import (
    extract_fields,
    parse_email,
    process_email,
    redact,
    scan_attachment,
)
from email_intake.parse import Attachment

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "invoice_email.eml"


def test_parse_headers_and_attachments():
    p = parse_email(SAMPLE.read_bytes())
    assert p.subject == "Invoice INV-2042 due"
    assert len(p.attachments) == 2
    assert {a.filename for a in p.attachments} == {"invoice.txt", "malware.exe"}


def test_redact_masks_and_counts_without_leaking():
    text = "email a@b.com call +1 (415) 555-0137 card 4111 1111 1111 1111"
    red, counts = redact(text)
    assert counts == {"CARD": 1, "EMAIL": 1, "PHONE": 1}
    for leak in ("a@b.com", "415", "4111"):
        assert leak not in red
    assert "[EMAIL]" in red and "[PHONE]" in red and "[CARD]" in red


def test_redact_keeps_money_and_dates():
    red, counts = redact("Amount $1,250.00 due 2026-05-15")
    assert "1,250.00" in red and "2026-05-15" in red
    assert counts == {}


def test_scan_blocks_executables():
    assert scan_attachment(Attachment("invoice.txt", "text/plain", 10, "h")).ok
    assert not scan_attachment(Attachment("malware.exe", "application/octet-stream", 10, "h")).ok


def test_extract_fields():
    f = extract_fields("Invoice INV-2042. Amount due: $1,250.00. Due date: 2026-05-15")
    assert f == {"invoice_number": "INV-2042", "amount": "1,250.00", "due_date": "2026-05-15"}


def test_pipeline_end_to_end():
    res = process_email(SAMPLE.read_bytes())
    assert res.fields["invoice_number"] == "INV-2042"
    assert any(not v.ok for v in res.attachments)           # the .exe is blocked
    assert "jane.doe@vendor.example" not in res.redacted_body
    assert res.redactions.get("CARD") == 1
