from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, HttpUrl, field_validator


class SourceConfig(BaseModel):
    name: str
    url: HttpUrl
    expected_fields: list[str] = Field(default_factory=list)
    cadence_seconds: float = Field(default=1.0, ge=0.0)

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("name must not be empty")
        return value


class AuditConfig(BaseModel):
    sources: list[SourceConfig]

    @classmethod
    def from_yaml(cls, path: Path) -> "AuditConfig":
        data = yaml.safe_load(path.read_text())
        if not isinstance(data, dict):
            raise ValueError("config must be a mapping")
        return cls.model_validate(data)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump()
