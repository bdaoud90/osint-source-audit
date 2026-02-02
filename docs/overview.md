# OSINT Source Audit

This repository provides a Python CLI for auditing public OSINT data sources based on
configurable metadata, including HTTP availability, latency, headers, and schema
expectations.

## Design goals

- Respect robots.txt and declared cadence to avoid overloading services.
- Provide structured JSON output for automation and Markdown output for reports.
- Keep the audit results deterministic and easy to diff.
