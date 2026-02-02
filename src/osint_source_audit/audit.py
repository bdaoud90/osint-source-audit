from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

import httpx

from .config import AuditConfig, SourceConfig
from .models import AuditReport, AuditSummary, SourceAuditResult


@dataclass
class RateLimiter:
    min_interval_seconds: float
    _last_request_time: float | None = None

    def wait(self) -> None:
        if self._last_request_time is None:
            self._last_request_time = time.monotonic()
            return
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < self.min_interval_seconds:
            time.sleep(self.min_interval_seconds - elapsed)
        self._last_request_time = time.monotonic()


class RobotsPolicy:
    def __init__(self, client: httpx.Client, timeout: httpx.Timeout) -> None:
        self._client = client
        self._timeout = timeout
        self._cache: dict[str, RobotFileParser] = {}
        self._errors: dict[str, str] = {}

    def is_allowed(self, url: str, user_agent: str = "osint-source-audit") -> bool:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base not in self._cache:
            self._cache[base] = self._fetch_robots(base)
        parser = self._cache[base]
        return parser.can_fetch(user_agent, url)

    def get_error(self, url: str) -> str | None:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        return self._errors.get(base)

    def _fetch_robots(self, base_url: str) -> RobotFileParser:
        parser = RobotFileParser()
        robots_url = f"{base_url}/robots.txt"
        try:
            response = self._client.get(robots_url, timeout=self._timeout)
            if response.status_code >= 400:
                self._errors[base_url] = f"robots.txt returned {response.status_code}"
                parser.parse([])
                if response.status_code == 404:
                    parser.allow_all()
                return parser
            parser.parse(response.text.splitlines())
            return parser
        except httpx.HTTPError as exc:
            self._errors[base_url] = f"robots.txt fetch failed: {exc}"
            parser.parse([])
            return parser


class AuditRunner:
    def __init__(
        self,
        config: AuditConfig,
        timeout_seconds: float = 10.0,
        user_agent: str = "osint-source-audit",
        client: httpx.Client | None = None,
        robots_policy: RobotsPolicy | None = None,
    ) -> None:
        self.config = config
        self.timeout = httpx.Timeout(timeout_seconds)
        self.user_agent = user_agent
        self.client = client or httpx.Client(headers={"User-Agent": self.user_agent})
        self.robots_policy = robots_policy or RobotsPolicy(self.client, self.timeout)
        self.rate_limiter = RateLimiter(min_interval_seconds=self._min_cadence())

    def _min_cadence(self) -> float:
        if not self.config.sources:
            return 0.0
        return min(source.cadence_seconds for source in self.config.sources)

    def run(self) -> AuditReport:
        results: list[SourceAuditResult] = []
        notes: list[str] = []

        for source in self.config.sources:
            self.rate_limiter.min_interval_seconds = source.cadence_seconds
            self.rate_limiter.wait()
            result = self._audit_source(source)
            robots_error = self.robots_policy.get_error(str(source.url))
            if robots_error:
                notes.append(f"{source.name}: {robots_error}")
            results.append(result)

        summary = AuditSummary(
            total_sources=len(results),
            successful=sum(1 for item in results if item.ok),
            failed=sum(1 for item in results if not item.ok),
            schema_valid=sum(1 for item in results if item.schema_valid),
        )
        return AuditReport(
            generated_at=datetime.now(timezone.utc),
            summary=summary,
            results=results,
            notes=notes,
        )

    def _audit_source(self, source: SourceConfig) -> SourceAuditResult:
        url = str(source.url)
        if not self.robots_policy.is_allowed(url, self.user_agent):
            return SourceAuditResult(
                name=source.name,
                url=url,
                ok=False,
                robots_allowed=False,
                error="Blocked by robots.txt",
            )

        start = time.monotonic()
        try:
            response = self.client.get(url, timeout=self.timeout)
            elapsed_ms = (time.monotonic() - start) * 1000
            headers = {k: v for k, v in response.headers.items()}
            last_modified = response.headers.get("Last-Modified")
            schema_valid, missing_fields, error = self._validate_schema(
                response, source.expected_fields
            )
            return SourceAuditResult(
                name=source.name,
                url=url,
                ok=response.is_success,
                status_code=response.status_code,
                response_time_ms=round(elapsed_ms, 2),
                headers=headers,
                last_modified=last_modified,
                schema_valid=schema_valid,
                missing_fields=missing_fields,
                error=error,
            )
        except httpx.TimeoutException:
            return SourceAuditResult(
                name=source.name,
                url=url,
                ok=False,
                error="Timeout",
            )
        except httpx.HTTPError as exc:
            return SourceAuditResult(
                name=source.name,
                url=url,
                ok=False,
                error=f"HTTP error: {exc}",
            )

    def _validate_schema(
        self, response: httpx.Response, expected_fields: Iterable[str]
    ) -> tuple[bool | None, list[str], str | None]:
        if not expected_fields:
            return None, [], None
        try:
            payload = response.json()
        except json.JSONDecodeError:
            return False, list(expected_fields), "Response was not valid JSON"

        if not isinstance(payload, dict):
            return False, list(expected_fields), "Expected JSON object"

        missing = [field for field in expected_fields if field not in payload]
        return len(missing) == 0, missing, None


def write_report(report: AuditReport, output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "report.json"
    md_path = output_dir / "report.md"

    json_path.write_text(json.dumps(report.to_dict(), indent=2))
    md_path.write_text(render_markdown(report))
    return json_path, md_path


def render_markdown(report: AuditReport) -> str:
    header = "| Name | URL | Status | Latency (ms) | Schema | Robots |"
    separator = "| --- | --- | --- | --- | --- | --- |"
    rows = [header, separator]

    for result in report.results:
        status = str(result.status_code) if result.status_code else "-"
        latency = f"{result.response_time_ms:.2f}" if result.response_time_ms else "-"
        schema = "n/a" if result.schema_valid is None else str(result.schema_valid)
        robots = "allowed" if result.robots_allowed else "blocked"
        rows.append(
            f"| {result.name} | {result.url} | {status} | {latency} | {schema} | {robots} |"
        )

    summary = report.summary
    lines = [
        "# OSINT Source Audit Report",
        "",
        f"Generated at: {report.generated_at.isoformat()}",
        "",
        "## Summary",
        f"- Total sources: {summary.total_sources}",
        f"- Successful checks: {summary.successful}",
        f"- Failed checks: {summary.failed}",
        f"- Schema valid: {summary.schema_valid}",
        "",
        "## Results",
        "",
        *rows,
    ]

    if report.notes:
        lines.extend(["", "## Notes"])
        lines.extend([f"- {note}" for note in report.notes])

    return "\n".join(lines)
