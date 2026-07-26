# `agents/`

The specialized AI agents that collaborate to investigate incidents. Each is a bounded
specialist with a single responsibility and a strict, schema-validated I/O contract. Agents
**never call one another directly** — the orchestration `graph/` routes shared state between
them (governing invariant #5).

## Packages
| Path | Agent | Built in sprint |
|---|---|---|
| `log_analyzer/` | Normalize + correlate logs → timeline | Log Analyzer Agent |
| `threat_detector/` | Verdict, IoCs, ATT&CK, severity | Threat Detector Agent |
| `cve_research/` | Relevant CVEs, CVSS, applicability, citations | CVE Research Agent |
| `incident_reporter/` | Executive + technical report | Incident Reporter |
| `patch_recommender/` | Prioritized remediation (human-approved) | Patch Recommendation Agent |
| `shared/` | Common contracts, guardrails, base abstractions | Alongside the agents |

## Cross-cutting rules (EDS §4)
Contract-first I/O; separate evidence from inference; emit a confidence score; least-privilege
tools; no lateral calls.

## Ownership
AI / Agents squad.

## Testing
Golden-fixture I/O tests, schema validity, guardrail adherence, and confidence calibration —
including adversarial prompt-injection cases in ingested content.
