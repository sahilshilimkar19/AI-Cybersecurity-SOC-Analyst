# `tests/`

The test and evaluation suites, mirroring the source tree (EDS §12). Runs via `pytest`.

## Categories (grown per sprint)
Unit · integration · agent · prompt-evaluation · graph · security · performance · regression ·
acceptance. Bootstrap ships the unit + smoke foundation.

## Current contents
| Path | Covers |
|---|---|
| `conftest.py` | Shared fixtures; isolates settings from local `.env` and cache. |
| `config/test_settings.py` | Defaults, env overrides, validation, production-safety, caching. |
| `config/test_logging.py` | Structured logging in console + JSON modes and level filtering. |
| `test_smoke.py` | Every monorepo package imports cleanly. |

## Conventions
Deterministic tests only (no flakes in the merge lane). AI behavior (prompt/RAG/agent evals)
is scored against thresholds in the sprints that introduce those components.
