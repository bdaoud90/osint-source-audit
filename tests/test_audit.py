from __future__ import annotations

import json
from pathlib import Path

import httpx

from osint_source_audit.audit import AuditRunner, write_report
from osint_source_audit.config import AuditConfig, SourceConfig
from osint_source_audit.models import AuditReport


class AllowAllRobots:
    def is_allowed(self, url: str, user_agent: str = "osint-source-audit") -> bool:
        return True

    def get_error(self, url: str) -> str | None:
        return None


def test_audit_runner_success() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 1, "name": "alpha", "updated_at": "2024"})

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    config = AuditConfig(
        sources=[
            SourceConfig(
                name="Sample",
                url="https://example.com/api",
                expected_fields=["id", "name", "updated_at"],
                cadence_seconds=0.0,
            )
        ]
    )

    runner = AuditRunner(config, client=client, robots_policy=AllowAllRobots())
    report = runner.run()

    assert report.summary.total_sources == 1
    assert report.summary.successful == 1
    assert report.summary.schema_valid == 1
    assert report.results[0].missing_fields == []


def test_audit_runner_schema_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 1})

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    config = AuditConfig(
        sources=[
            SourceConfig(
                name="Sample",
                url="https://example.com/api",
                expected_fields=["id", "name"],
                cadence_seconds=0.0,
            )
        ]
    )

    runner = AuditRunner(config, client=client, robots_policy=AllowAllRobots())
    report = runner.run()

    assert report.summary.schema_valid == 0
    assert report.results[0].schema_valid is False
    assert report.results[0].missing_fields == ["name"]


def test_write_report(tmp_path: Path) -> None:
    report = AuditReport.model_validate(
        {
            "generated_at": "2024-01-01T00:00:00Z",
            "summary": {
                "total_sources": 1,
                "successful": 1,
                "failed": 0,
                "schema_valid": 1,
            },
            "results": [
                {
                    "name": "Sample",
                    "url": "https://example.com",
                    "ok": True,
                    "status_code": 200,
                    "response_time_ms": 5.2,
                    "headers": {"content-type": "application/json"},
                    "last_modified": None,
                    "schema_valid": True,
                    "missing_fields": [],
                    "robots_allowed": True,
                    "error": None,
                }
            ],
            "notes": [],
        }
    )

    json_path, md_path = write_report(report, tmp_path)

    assert json_path.exists()
    assert md_path.exists()
    payload = json.loads(json_path.read_text())
    assert payload["summary"]["total_sources"] == 1
