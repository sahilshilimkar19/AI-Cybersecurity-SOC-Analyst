# `config/`

The typed, validated **configuration and structured-logging foundation** (EDS §3.14).

## Contents
| File | Purpose |
|---|---|
| `settings.py` | `Settings` (pydantic-settings): `SOC_`-prefixed env + `.env`, validated, fail-fast; `get_settings()` cached singleton. |
| `logging.py` | `configure_logging()` / `get_logger()`: structlog JSON or console output at the configured level. |

## Rules
- Fail-fast on invalid configuration at startup (a misconfigured process must not run).
- **Secrets never live here** — they are resolved at runtime from the external secret store
  in the sprints that introduce them.
- All environment-specific behavior flows through this layer; no config drift into code.

## Ownership
Security / Platform squad.

## Built in
The **Bootstrap** sprint (this is the sprint's substantive code). Configuration variables are
extended by later sprints as new capabilities are added.

## Testing
`tests/config/` covers default values, environment overrides, production-safety validation,
and singleton caching, plus that logging configures without error in both render modes.
