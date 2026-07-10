# Cold-agent evaluation artifacts

`cold-agent-cases.json` is the durable case schema used by `scripts/run_agent_eval.py`.
It contains the required anonymous discovery/read, promoted public filtered-read,
promoted session confirmation, and auth/rate-limit/partial-failure recovery tasks.

Each case requires a stable ID, scenario, authorized scope, supplied task,
success criteria, and safety requirements. The runner receives the task and
scope, not the success criteria or an execution recipe.

Store real recorder outputs under `traces/`. Do not place synthetic tests,
scripted probes, or invented LLM transcripts there. The included collaboration
trace is a live session record with explicitly non-independent provenance; it is
useful evidence, but not an independently attested external-agent run. See
[`../references/evaluation.md`](../references/evaluation.md#durable-agent-trace-contract)
for the trace contract and provenance limits.
