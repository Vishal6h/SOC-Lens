"""Small serializable models used by ingestion adapters and staging."""
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class IngestionLimits:
    max_upload_bytes: int
    max_records: int
    max_columns: int
    max_field_bytes: int
    max_active_imports: int


@dataclass(frozen=True)
class ImportIssue:
    level: str
    code: str
    reason: str
    source_file: str
    record_number: int | None = None
    field: str | None = None

    def document(self) -> dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value is not None}


@dataclass
class ImportJob:
    import_id: str
    created_at: str
    source_format: str
    source_profile: str
    original_filename: str
    file_sha256: str
    mapping_profile_id: str
    mapping_profile_version: int
    record_count: int = 0
    accepted_records: int = 0
    rejected_records: int = 0
    warnings: int = 0
    status: str = "received"
    canonical_output_sha256: str | None = None
    categories_produced: list[str] = field(default_factory=list)
    field_mapping: dict[str, str] = field(default_factory=dict)
    issues: list[ImportIssue] = field(default_factory=list)
    fragment: dict[str, Any] = field(default_factory=dict)

    def stored_document(self) -> dict[str, Any]:
        document = asdict(self)
        document["issues"] = [issue.document() for issue in self.issues]
        return document

    def public_document(self, *, include_issues=True) -> dict[str, Any]:
        document = self.stored_document()
        document.pop("fragment", None)
        if not include_issues:
            document.pop("issues", None)
        return document

    @classmethod
    def from_document(cls, document: dict[str, Any]):
        value = dict(document)
        value["issues"] = [ImportIssue(**issue) for issue in value.get("issues", [])]
        return cls(**value)
