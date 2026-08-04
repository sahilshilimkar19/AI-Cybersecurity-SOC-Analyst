# `integrations/`

Isolated adapters to external and enterprise systems (EDS §3.12, §7). Each adapter is its own
failure domain with a cache, rate limiter, and circuit breaker, so one dependency's outage
degrades exactly one capability (invariant #6).

| Integration | Purpose | First needed in |
|---|---|---|
| NVD CVE API | CVE records + CVSS | RAG / CVE Research |
| MITRE ATT&CK / CWE | Technique taxonomy | RAG / Threat Detector |
| VirusTotal | IoC reputation/enrichment | Threat Detector |
| GitHub advisories | Package vulnerabilities | CVE Research |
| SIEM (Splunk / Elastic), log sources | Evidence ingestion | Log Analyzer |
| Slack, SMTP | Human notification | Notifications |

## Shipped
| Module | Covers |
|---|---|
| `log_sources.py` | File + in-process log connectors (SIEM adapters satisfy the same protocol) |
| `resilience.py` | Shared TTL cache, token-bucket rate limiter, circuit breaker |
| `threat_intel.py` | IoC reputation: unavailable-by-default, in-memory, VirusTotal |

## Rules
Read-only by default for data sources (no enforcement authority); validate/normalize all
external data as untrusted; enforce per-integration rate limits. Failures are returned as
typed results, never raised. Estate-internal indicators are never submitted to a third
party — enrichment must not leak internal topology.

## Ownership
Backend + Security / Platform squads.

## Built in
From the sprints that first require each integration.

## Testing
Adapter tests against mocks/sandboxes; resilience tests (circuit breaker, cache fallback,
staleness flags).
