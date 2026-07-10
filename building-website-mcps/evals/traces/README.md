# Real trace destination

This directory is deliberately free of fabricated agent evidence. Add a real
`run_agent_eval.py` result here only after a cold session completes. Preserve
the recorder JSON, its redacted transcript artifact, runner kind, real session
reference, agent identity/version, and any failure outcome.

A recorded collaboration session must use the `collaboration_agent` runner kind
and will be labelled `collaboration_agent_evidence`; it must not be presented
as independently attested external-agent proof.

`cold-agent-public-promoted.json` records one such live collaboration-agent
session. Its zero timing/response-byte fields are explicitly uninstrumented,
not measurements. It is a durable RED→GREEN companion to the deterministic
matrix, not a substitute for an independently attested external-agent run.
