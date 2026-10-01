"""Bounded standard-library CSV and JSON source adapters."""
import csv
import io
import json


class AdapterError(ValueError):
    def __init__(self, code, reason, record_number=None, field=None):
        super().__init__(reason)
        self.code, self.reason = code, reason
        self.record_number, self.field = record_number, field


def _decode(raw):
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise AdapterError("INVALID_UTF8", "Evidence files must be valid UTF-8.") from exc


def parse_csv(raw, limits):
    text = _decode(raw)
    try:
        rows = csv.reader(io.StringIO(text, newline=""), strict=True)
        header = next(rows, None)
        if header is None:
            raise AdapterError("MISSING_HEADER", "CSV file does not contain a header row.")
        header = [value.strip() for value in header]
        if len(header) > limits.max_columns:
            raise AdapterError("EXCESSIVE_COLUMNS", f"CSV exceeds the {limits.max_columns}-column limit.")
        if any(len(value.encode("utf-8")) > limits.max_field_bytes for value in header):
            raise AdapterError("FIELD_TOO_LARGE", "A CSV header exceeds the configured field limit.", 1)
        if any(not value for value in header):
            raise AdapterError("BLANK_HEADER", "CSV headers must not be blank.")
        if len(set(header)) != len(header):
            raise AdapterError("DUPLICATE_HEADER", "CSV headers must be unique.")
        records, rejected = [], []
        for row_number, row in enumerate(rows, 2):
            if len(records) + len(rejected) >= limits.max_records:
                raise AdapterError("EXCESSIVE_RECORDS", f"CSV exceeds the {limits.max_records}-record limit.")
            if len(row) != len(header):
                rejected.append((row_number, "MALFORMED_ROW", f"Row has {len(row)} fields; expected {len(header)}."))
                continue
            records.append((row_number, dict(zip(header, row))))
        return header, records, rejected
    except csv.Error as exc:
        raise AdapterError("MALFORMED_CSV", f"CSV could not be parsed: {exc}", getattr(rows, "line_num", None)) from exc


def parse_json(raw, limits):
    text = _decode(raw)
    try:
        value = json.loads(text, parse_constant=lambda constant: (_ for _ in ()).throw(ValueError(constant)))
    except (json.JSONDecodeError, ValueError) as exc:
        raise AdapterError("MALFORMED_JSON", "JSON could not be parsed as a finite-value document.") from exc
    if isinstance(value, list):
        records = value
    elif isinstance(value, dict) and set(value) == {"records"} and isinstance(value["records"], list):
        records = value["records"]
    else:
        raise AdapterError("UNSUPPORTED_JSON_SHAPE", "Expected a JSON array or an object containing only a records array.")
    if len(records) > limits.max_records:
        raise AdapterError("EXCESSIVE_RECORDS", f"JSON exceeds the {limits.max_records}-record limit.")
    rejected = [(index, "INVALID_RECORD", "JSON source record must be an object.")
                for index, record in enumerate(records, 1) if not isinstance(record, dict)]
    valid_records = [(index, record) for index, record in enumerate(records, 1) if isinstance(record, dict)]
    columns = sorted(set().union(*(record.keys() for _, record in valid_records))) if valid_records else []
    if any(len(column.encode("utf-8")) > limits.max_field_bytes for column in columns):
        raise AdapterError("FIELD_TOO_LARGE", "A JSON field name exceeds the configured field limit.")
    if len(columns) > limits.max_columns:
        raise AdapterError("EXCESSIVE_COLUMNS", f"JSON records exceed the {limits.max_columns}-field limit.")
    return columns, valid_records, rejected
