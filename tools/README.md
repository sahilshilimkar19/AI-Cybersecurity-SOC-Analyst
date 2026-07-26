# `tools/`

Deterministic capabilities that agents invoke — parsers, normalizers, entity/IoC extractors,
CVSS interpreter, correlators, and integration-lookup wrappers. Kept separate from agent
reasoning so they are independently unit-testable (EDS §3.7).

## Rules
- **Least privilege:** each agent may call only its allow-listed tools.
- Validate arguments and results; treat external data as untrusted.
- Return typed failures (never swallow errors) so agents can degrade gracefully.

## Ownership
AI / Agents + Backend squads.

## Built in
From the agent sprints onward (each tool alongside the agent that needs it).

## Testing
High-coverage unit tests; least-privilege allow-list enforcement.
