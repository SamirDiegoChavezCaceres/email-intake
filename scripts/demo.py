"""Process a sample email into a safe intake record.

    python scripts/demo.py
"""

from __future__ import annotations

from pathlib import Path

from email_intake import process_email

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "invoice_email.eml"


def rule(title: str) -> None:
    print(f"\n=== {title} ===")


def main() -> None:
    res = process_email(SAMPLE.read_bytes())

    rule("1. Parsed metadata")
    print(f"  from   : {res.sender}")
    print(f"  subject: {res.subject}")
    print(f"  date   : {res.date}")

    rule("2. Attachment scan")
    for v in res.attachments:
        print(f"  {'OK  ' if v.ok else 'BLOCK'} {v.filename:14} -> {v.reason}")

    rule("3. PII redaction (counts only, values never kept)")
    print(f"  removed: {res.redactions}")
    print("  body after redaction:")
    for line in res.redacted_body.splitlines():
        if line.strip():
            print(f"    {line}")

    rule("4. Extracted intake fields")
    for k, v in res.fields.items():
        print(f"  {k:15}: {v}")


if __name__ == "__main__":
    main()
