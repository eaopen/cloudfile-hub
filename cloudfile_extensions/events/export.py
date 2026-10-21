"""Internal bounded CSV generation; publish an artifact only after exhaustion.

The async job adapter must discard partial output on failure and authorize result
downloads again. This generator is not a public streaming download endpoint.
"""

import csv
import io

from ..common.errors import ContractError
from .query import AuditReader
from .privacy import redact_event


def csv_cell(value):
    if value is None:
        return ""
    if type(value) not in (str, int):
        raise ContractError("AUDIT_UNAVAILABLE", "Audit export field is invalid", 503)
    text = str(value)
    # CSV quoting alone does not prevent spreadsheet formula evaluation.
    # Detect formulas behind whitespace/BOM and control-prefixed cells too.
    probe = text.lstrip()
    while probe.startswith("\ufeff"):
        probe = probe[1:].lstrip()
    if (probe.startswith(("=", "+", "-", "@")) or
            any(ord(char) < 32 or ord(char) == 127 for char in text)):
        return "'" + text.replace("\x00", "")
    return text


class AuditCSV:
    def __init__(self, reader, *, authorize_export, redact,
                 max_rows=10000, max_bytes=10 * 1024 * 1024, max_pages=100):
        if not callable(authorize_export) or not callable(redact):
            raise ValueError("trusted export authorization and redaction are required")
        for value, ceiling in ((max_rows, 100000), (max_bytes, 100 * 1024 * 1024), (max_pages, 1000)):
            if type(value) is not int or not 1 <= value <= ceiling:
                raise ValueError("invalid audit export budget")
        self.reader, self.authorize, self.redact = reader, authorize_export, redact
        self.max_rows, self.max_bytes, self.max_pages = max_rows, max_bytes, max_pages

    @staticmethod
    def _row(values):
        buffer = io.StringIO(newline="")
        csv.writer(buffer, lineterminator="\r\n", quoting=csv.QUOTE_ALL).writerow(values)
        return buffer.getvalue().encode("utf-8")

    def generate(self, **query):
        if {"cursor", "limit"} & query.keys():
            raise ContractError("INVALID_REQUEST", "Export must begin at the query start", 400)
        actor, repo = query.get("actor"), query.get("repo_id")
        cursor, count, size = None, 0, 0
        header = self._row(AuditReader.FIELDS)
        for page_number in range(self.max_pages):
            if self.authorize(actor, repo) is not True:
                raise ContractError("FORBIDDEN", "Audit export scope is not available", 403)
            page = self.reader.list(**query, limit=200, cursor=cursor)
            if page_number == 0:
                size = len(header)
                if size > self.max_bytes:
                    raise ContractError("EXPORT_LIMIT", "Audit export exceeds its budget", 413)
                yield header
            for event in page["items"]:
                # Redact a copy, then serialize only known fields; a redactor
                # cannot introduce secret/raw payload columns into the CSV.
                value = redact_event(self.redact, actor, event)
                row = self._row(csv_cell(value[field]) for field in AuditReader.FIELDS)
                count += 1
                size += len(row)
                if count > self.max_rows or size > self.max_bytes:
                    raise ContractError("EXPORT_LIMIT", "Audit export exceeds its budget", 413)
                yield row
            following = page["next_cursor"]
            if following is None:
                return
            if following == cursor:
                raise ContractError("AUDIT_UNAVAILABLE", "Audit export did not advance", 503)
            cursor = following
        raise ContractError("EXPORT_LIMIT", "Audit export exceeds its budget", 413)
