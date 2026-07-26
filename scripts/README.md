# `scripts/`

Repeatable operational and developer scripts — e.g. knowledge-base seeding, database
migrations, and local bootstrap helpers (EDS §10).

## Ownership
Security / Platform squad.

## Conventions
Scripts are idempotent where possible, take configuration from `config/` / environment (never
hard-coded secrets), and are documented at the top of each file.

## Built in
Populated as operational needs arise (first substantive scripts land with the Database + Models
and Deployment sprints).
