from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SourceAuditResult(BaseModel):
    name: str
    url: str
    ok: bool
    status_code: int | None = None
    response_time_ms: float | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    last_modified: str | None = None
    schema_valid: bool | None = None
    missing_fields: list[str] = Field(default_factory=list)
    robots_allowed: bool = True
    error: str | None = None


class AuditSummary(BaseModel):
    total_sources: int
    successful: int
    failed: int
    schema_valid: int


class AuditReport(BaseModel):
    generated_at: datetime
    summary: AuditSummary
    results: list[SourceAuditResult]
    notes: list[str] = Field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
