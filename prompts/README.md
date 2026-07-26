# `prompts/`

Versioned **prompt assets** and their contracts (EDS §9). Prompts are treated as
code-reviewed, evaluated, change-controlled assets — not tribal knowledge.

A shared **system preamble** will encode the governing invariants (human-in-the-loop,
evidence-vs-inference separation, untrusted-data separation, citation requirement); per-agent
prompts specialize it. Every prompt maps to a validated output schema in `models/`.

> The prompt **text** is authored in the sprint that implements each agent; this folder holds
> those assets plus a version manifest. Nothing is authored during Bootstrap.

## Ownership
AI / Agents squad.

## Testing
Per-prompt evaluation suites gate any change (correctness, format adherence, refusal,
injection resistance).
