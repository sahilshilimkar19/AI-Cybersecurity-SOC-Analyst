# `tools/`

Deterministic capabilities that agents invoke — parsers, normalizers, entity/IoC extractors,
CVSS interpreter, correlators, and integration-lookup wrappers. Kept separate from agent
reasoning so they are independently unit-testable (EDS §3.7).

## Shipped
| Module | Covers |
|---|---|
| `parsers.py` | Six log formats → normalized records |
| `extraction.py` | Entities (hosts, users, addresses, hashes, paths, processes) |
| `correlation.py` | Time-window correlation and notability scoring |
| `iocs.py` | Indicator extraction, internal/external classification, defanging |
| `detection.py` | The detection rule catalogue and its engine |
| `attack.py` | Pinned MITRE ATT&CK catalogue and the signal → technique mapper |
| `severity.py` | Severity score, verdict, triage priority, escalation |
| `cvss.py` | CVSS v3.1 vector parsing, base scoring, plain-language reading |
| `versions.py` | Version comparison, published-range matching, CVE applicability |
| `cwe.py` | Pinned MITRE CWE catalogue with plain explanations |

## Rules
- **Least privilege:** each agent may call only its allow-listed tools.
- Validate arguments and results; treat external data as untrusted.
- Return typed failures (never swallow errors) so agents can degrade gracefully.
- **Pure functions of their inputs.** A tool states what is present in the evidence;
  composing that into a verdict belongs to the agent that called it.
- **No invented vocabulary.** A technique identifier absent from the pinned catalogue is
  dropped, never described.

## Ownership
AI / Agents + Backend squads.

## Built in
From the agent sprints onward (each tool alongside the agent that needs it).

## Testing
High-coverage unit tests; least-privilege allow-list enforcement.
