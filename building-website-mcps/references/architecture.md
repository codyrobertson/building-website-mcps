# MCP architecture and promotion gates

Use this after the route/action graph exists and before implementation planning.

## Contents

- [Layers](#layers)
- [Native promotion](#native-promotion)
- [Tool surface](#tool-surface)
- [Envelope and latency](#envelope-and-latency)
- [Writes and files](#writes-and-files)

## Layers

1. **Auth/session adapter** — least privilege, refresh, redaction, connection reuse.
2. **Transport clients** — typed HTTP or local CLI calls; browser fallback isolated.
3. **Capability graph** — compact metadata, prerequisites, schemas, sequencing, safety.
4. **Domain operations** — stable intent-level functions shared by MCP tools and tests.
5. **MCP surface** — small discovery layer, high-value native tools, bounded resources.
6. **Companion skill** — cold-start setup, discovery, examples, safety, recovery.

The MCP transport is independent of target auth. Prefer STDIO for a local package unless remote multi-user deployment is a requirement; support Streamable HTTP only with an explicit deployment/auth design.

## Native promotion

Promote a graph node only when all are true:

- Stable request/response or CLI contract is proven.
- It appears in representative agent tasks.
- Inputs can be typed and validated.
- Auth and side effects are understood.
- Direct execution beats UI fallback in calls, latency, reliability, or envelope size.
- Unit, contract, and authorized E2E tests are feasible.

Keep unstable, low-value, or UI-only nodes discoverable as fallback. Native coverage is not endpoint coverage.

## Tool surface

Start with compact discovery operations such as `search_capabilities`, `describe_capabilities`, and `plan_workflow`. Return IDs and summaries first; load schemas and examples only for selected nodes.

Expose domain tools by intent and shared schema, not one tool per route. Use projections, filters, cursors, and bounded `limit`. Batch only independent or explicitly batch-safe operations. Sequential workflows must surface prerequisites and partial completion.

Avoid a universal raw-request tool unless it is restricted to a validated allowlist and the user explicitly needs an escape hatch. Raw requests weaken safety, discoverability, and schema guarantees.

## Envelope and latency

Define budgets in `spec.md`, then measure them. Defaults are hypotheses, not universal limits.

- Reuse clients, sessions, DNS/TLS connections, and caches where safe.
- Return compact structured data plus `next_cursor`, not prose dumps.
- Offer summary/detail levels and field projection.
- Paginate before truncating; state omissions explicitly.
- Benchmark representative tasks, not isolated ping latency.
- Record p50/p95, calls, bytes, tool-description tokens, and task success.

## Writes and files

Writes need idempotency strategy, clear side-effect annotations, and dry-run when supported. Define confirmation policy by risk and environment in `spec.md`: destructive and production-scoped changes normally confirm; routine sandbox writes may not. Retries must not duplicate writes.

For uploads/downloads, prefer streams, temporary file paths, object references, or signed URLs. Validate size, type, checksum, destination, and cleanup. Never route large binary data through model-visible base64.
