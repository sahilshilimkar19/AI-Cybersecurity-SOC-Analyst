"""Response and request contracts for the analyst-facing API.

These are **projections**, not the domain models. The dashboard reads what the
backend persisted, and the shapes here are deliberately narrower than the graph
state or the agent outputs: a UI contract that mirrored internal structures would
force every internal refactor through the browser.

Two properties are carried by every projection that renders an AI-derived claim:
its **confidence** and its **provenance** (SAD §13). A screen that shows a verdict
without showing how strongly it is held, or where it came from, invites exactly
the rubber-stamping the human gate exists to prevent.
"""
