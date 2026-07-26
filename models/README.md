# `models/`

The canonical typed **contracts** shared across every layer — domain entities, graph-state
schema, agent I/O schemas, API DTOs, and event schemas (EDS §3.13). Everything depends inward
on these shapes, so this layer has no dependencies of its own.

## Rules
Backward-compatible evolution or an explicit version bump; no breaking change without a
migration and updated consumers.

## Ownership
Shared (all squads).

## Built in
The **Database + Models** sprint. Not implemented during Bootstrap — only the empty package
exists so downstream layers have a stable import target.

## Testing
Schema validation and backward-compatibility tests.
