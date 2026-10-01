# email-intake

Turn messy inbound email into a safe, structured intake record. Parse the
message, scan its attachments, **redact PII**, and pull out the fields you care
about, the first mile of any "email your invoice/ticket to us" workflow.

## Demo

![demo](assets/demo.gif)

## What it does

1. **Parse** a raw `.eml` into sender, subject, date, body, and attachments
   (stdlib `email`, no dependencies).
2. **Scan** attachments: block dangerous extensions (`.exe`, `.js`, ...) and
   oversize files; hash the rest.
3. **Redact PII** from the body: emails, phone numbers, and (Luhn-checked)
   card numbers are masked. The result keeps only **counts by type**, never the
   values, so the audit trail does not re-leak what it redacted.
4. **Extract** intake fields (invoice/order number, amount, due date).

```python
from email_intake import process_email

res = process_email(open("message.eml", "rb").read())
res.attachments      # [ScanVerdict(filename='malware.exe', ok=False, ...)]
res.redactions       # {'EMAIL': 1, 'PHONE': 1, 'CARD': 1}
res.redacted_body    # "... Email [EMAIL] or call [PHONE]. Card [CARD] ..."
res.fields           # {'invoice_number': 'INV-2042', 'amount': '1,250.00', ...}
```

```bash
pip install -e .
python scripts/demo.py
```

## Tests

```bash
pip install -e ".[dev]"
pytest
```

Covers parsing, that redaction masks and counts without leaking the values (and
leaves money and dates alone), that the scanner blocks executables, and the
end-to-end pipeline on a sample email.

## Limitations and next steps

- Redaction is regex-based: it catches common emails, phones and card numbers,
  not every PII shape (names, addresses). High-stakes use wants an NER model.
- Field extraction is regex too; real invoices need a document-AI extractor.
- Next: OCR for PDF/image attachments, and an allowlist of trusted senders.

## License

MIT.
