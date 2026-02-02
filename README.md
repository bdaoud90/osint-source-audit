# OSINT Source Audit

## Overview
OSINT Source Audit is a Python CLI that inspects public data sources defined in a YAML
configuration and produces structured reports. It checks availability, HTTP status,
response latency, headers (including `Last-Modified` when present), and validates sample
responses against expected schemas.

## Use cases
- Vetting the reliability of public OSINT feeds before integrating them into workflows.
- Monitoring external status endpoints for incident response readiness.
- Building compliance evidence for source handling and rate-limit adherence.

## Features
- `audit` CLI command powered by Typer and Rich.
- YAML-driven configuration for sources, expected schema fields, and cadence.
- Structured JSON output plus human-readable Markdown reports.
- Robots.txt checking and per-source rate limiting.
- Graceful error handling and configurable timeouts.

## Quickstart
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .

osint-source-audit audit --config examples/config.yaml --output reports
```

## Configuration
Create a YAML file that defines the sources you want to audit.

```yaml
sources:
  - name: Example JSON Source
    url: https://example.com/api/sample.json
    expected_fields:
      - id
      - name
      - updated_at
    cadence_seconds: 1.5
```

Fields:
- `name`: Human-friendly identifier for the source.
- `url`: Fully-qualified URL to audit (only user-provided URLs are fetched).
- `expected_fields`: Optional list of top-level JSON keys expected in the response.
- `cadence_seconds`: Minimum delay between requests for this source.

## Example output
**report.json** (excerpt):
```json
{
  "generated_at": "2024-01-01T00:00:00+00:00",
  "summary": {
    "total_sources": 1,
    "successful": 1,
    "failed": 0,
    "schema_valid": 1
  }
}
```

**report.md** (excerpt):
```markdown
| Name | URL | Status | Latency (ms) | Schema | Robots |
| --- | --- | --- | --- | --- | --- |
| Example JSON Source | https://example.com/api/sample.json | 200 | 95.00 | True | allowed |
```

## Ethical use
Use this tool only with sources that permit automated access. Always comply with legal
restrictions, terms of service, and robots.txt directives for each source.

## Limitations
- Schema validation is limited to top-level JSON keys.
- The tool does not attempt retries or exponential backoff by default.
- Robots.txt fetch failures default to permissive behavior (logged in report notes).

## Security notes
- Store sensitive endpoints in private configuration files.
- Avoid embedding credentials in URLs whenever possible.
- Run audits from controlled environments to prevent unintended data exposure.

## License
MIT. See [LICENSE](LICENSE).
