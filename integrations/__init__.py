"""Integrations layer — isolated adapters to external and enterprise systems.

Each adapter (NVD, MITRE ATT&CK, VirusTotal, GitHub advisories, SIEM, log
sources, Slack, SMTP) is its own failure domain with a cache, rate limiter, and
circuit breaker. Adapters are read-only for data sources; one dependency's
outage degrades one capability only (governing invariant #6).

Populated from the sprints that first require each integration.
See docs/ENGINEERING_DESIGN_SPEC.md §3.12 and §7.
"""
