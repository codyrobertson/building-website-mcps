---
name: building-website-mcps
description: Use when turning an authorized website, web application, public API, browser workflow, or local CLI into a production MCP server, especially when auth, route discovery, UI actions, uploads, downloads, batching, or cold-agent usability are uncertain.
---

# Building Website MCPs

## Overview

Build from evidence, not guesses. Produce a resumable route/action graph first, then promote only proven capabilities into a compact, fast MCP with a companion skill and unit, contract, E2E, performance, and agent evaluations.

**Authorization is a gate, not a footnote.** Work only on public surfaces or accounts and data the user is authorized to access. Never bypass access controls, CAPTCHAs, rate limits, or anti-bot protections; never persist raw credentials in artifacts.

## Required workflow

For implementation work, use these skills when available:

- **REQUIRED SUB-SKILL:** Use `superpowers:brainstorming` before choosing the architecture.
- **REQUIRED SUB-SKILL:** Use `superpowers:writing-plans` before editing the generated MCP.
- **REQUIRED SUB-SKILL:** Use `superpowers:test-driven-development` for every behavior change.
- **REQUIRED SUB-SKILL:** Use `superpowers:systematic-debugging` when evidence or tests disagree.
- **REQUIRED SUB-SKILL:** Use `superpowers:verification-before-completion` before claiming readiness.

If workers are available and delegation is authorized, assign bounded roles: reconnaissance, modeling, test/evaluation, and adversarial review. Keep one lead responsible for stage gates and artifact merges. Workers must write findings to the durable workspace; chat-only findings do not count.

## Start or resume

1. Find the target repository and read its instructions.
2. If `.website-mcp/state.json` exists, validate it and resume its dependency-satisfied workstream. Do not restart discovery.
3. Otherwise run:

```bash
python <skill-dir>/scripts/scaffold_workspace.py <project-dir> <target-url>
```

For a credential-free local CLI, the only CLI target is `cli://local` and an explicit, typed contract is mandatory. This lane performs no HTTP crawl or OpenAPI fetch: it creates an empty OpenAPI 3.1 route map and discovers only the contract's allowlisted commands.

```bash
python <skill-dir>/scripts/scaffold_workspace.py <project-dir> cli://local
# approve the scope checkpoint after reviewing spec.md
python <skill-dir>/scripts/discover_target.py <project-dir> cli://local \
  --cli-contract ./cli-contract.json
```

The contract must declare `execution.mode: "argv"`, `execution.shell: false`, and typed command schemas. Use an environment executable reference (for example, `env:MY_CLI`) for any command intended for generated MCP execution; do not supply raw target paths, userinfo, free-form shell strings, or raw credential values.

4. Read [artifact-contract.md](references/artifact-contract.md) before modifying generated artifacts.
5. Run the validator after every stage transition:

```bash
python <skill-dir>/scripts/validate_workspace.py <project-dir>
```

Use `transition_stage.py` for every stage change; its signed, hash-linked transition history—not a hand-edited snapshot—is authoritative. Completed stages need evidence IDs. Use `blocked` only for a demonstrated external dependency and record the exact unblock condition.

## Stage gates

### 1. Authorize and specify

Brainstorm concrete agent tasks and define success, forbidden actions, target accounts/data, destructive-action confirmation, and measurable budgets in `spec.md`. Include discovery tokens, calls per representative task, p95 latency, and maximum response bytes.

Do not crawl or authenticate until authorized scope is explicit.

### 2. Establish auth

Test the least privileged viable lane in this order:

1. Anonymous documented/public HTTP.
2. User-provided API key, bearer, OAuth, or service account reference.
3. User-authorized cookie/session reuse through a browser-session handle, OS keychain, or secret-provider reference, with CSRF and refresh behavior.
4. Browser-observed UI traffic or UI automation when no stable HTTP contract exists.

STDIO is the MCP transport and `stdio` is a CLI/action-graph surface; neither is an auth mode. Capture local command auth/environment requirements in `cli.json`.

Record acquisition, injection, expiry, refresh, logout, storage, redaction, and failure evidence in `auth.json`. Store only secret references or environment-variable names. Prove auth with a harmless read and prove failure with a deliberately absent/expired test fixture.

### 3. Discover external routes and actions

Use multiple evidence sources: official docs or OpenAPI, HTML forms, authorized browser network traffic, client code, and CLI help/source. Index every observation in `evidence-index.json` with source, capture time, freshness limit, redaction result, confidence, and auth requirement.

Separate these dimensions:

- `method`: HTTP GET/POST/PUT/PATCH/DELETE or CLI invocation.
- `type`: auth, read, create, update, delete, action, upload, or download.
- `surface`: http, ui, hybrid, or stdio.

Do not treat a UI intent such as “edit profile form” as identical to `PATCH /profile`. Link them in the graph when the UI action delegates to HTTP. Keep browser-only behavior as UI until its HTTP contract is independently verified.

### 4. Normalize the map and graph

Put client-facing HTTP operations in `openapi.json`, including authorized authenticated endpoints used by the website; “external” does not mean anonymous. Exclude pure UI gestures and local CLI commands. Every operation must contain the stable discovery triple:

```json
"x-mcp": { "route": "/items/{id}", "type": "update", "surface": "hybrid" }
```

Keep method in the OpenAPI operation key. The three core keys are required; additional `x-*` metadata is allowed. Put auth, evidence, confidence, schemas, side effects, pagination, idempotency, and retry details in standard OpenAPI fields or the action graph, not in the triple.

Build `action-graph.json` with capability nodes and typed edges for `requires`, `produces`, `consumes`, `precedes`, `alternative`, and `contains`. Classify execution as independent, sequential, batch, paginated, upload-stream, or download-stream. When a workflow has multiple execution modes, decompose it into single-mode nodes and connect them; for example upload → validate → batch commit → result download. Record local command schemas in `cli.json`. See [artifact-contract.md](references/artifact-contract.md).

Run discovery as a loop, not a crawl: record a hypothesis, planned observation, evidence result, model change, unresolved question, and next probe in `discovery-iterations.jsonl`. Required signed checkpoints are scope, auth (when non-anonymous), native floor, and final coverage. `approve_checkpoint.py` requires `WEBSITE_MCP_APPROVAL_KEY`; no agent may self-attest approval by editing workspace JSONL.

### 5. Choose the native MCP floor

Read [architecture.md](references/architecture.md). Promote a capability to native only when its contract is stable, useful in representative tasks, safe to expose, and cheaper or more reliable than UI automation.

Prefer:

- A tiny discovery layer: search capabilities, describe selected capabilities, and inspect workflow prerequisites.
- Typed domain tools for high-value actions, grouped by user intent rather than one tool per endpoint. Annotate ordinary writes with the confirmation policy chosen in `spec.md`; risk and environment determine confirmation, not the mere presence of a write.
- Direct HTTP/CLI adapters, connection and session reuse, projection, cursor pagination, and bounded batch operations.
- File paths, signed URLs, or streams for upload/download; never place large base64 blobs in model context.

Keep UI fallback explicit and observable. Do not call browser automation “native.”

### Capability promotion gate

Discovery must leave every prospective executable capability at `native: "candidate"` with an explicit coverage gap. A candidate becomes executable only when a fresh, SHA-256-valid `e2e` or `contract` artifact names that capability and exactly its graph `operations` and `commands` in `promotion.bindings`. Route discovery, source code, and docs are never enough.

After recording redacted proof from the real fixture/sandbox, promote it through the lock-scoped command rather than editing `native` or coverage by hand:

```bash
python scripts/record_e2e_proof.py <project-dir> <capability-id> \
  --evidence-id <evidence-id> \
  --operations-json '["<operation-id>"]' \
  --commands-json '[]' \
  --argv-file ./real-e2e.argv.json
python scripts/promote_capabilities.py <project-dir> <capability-id> --evidence <evidence-id>
python scripts/validate_workspace.py <project-dir> --level build
```

`record_e2e_proof.py` runs only explicit argv JSON (inline or file) with no shell and saves no raw argv/stdout/stderr; its evidence holds bounded byte counts and SHA-256 digests. It rejects nonzero/timeout/oversized commands and secret-bearing output. It only attests that the supplied command exited successfully: choose a real, authorized E2E or contract test and declare every operation/CLI command it exercises. The promoter then fails without changing graph or coverage when proof is stale, hash-invalid, unsafe, discovery-only, incomplete for a hybrid binding, or tied to another operation/CLI command. Generate the MCP only after this build gate; `execute_capability` exposes promoted nodes and refuses candidates.

### 6. Specify, plan, and implement with TDD

Freeze the initial representative tasks and failure cases before implementation. Write a detailed plan that traces each native tool to graph nodes, route evidence, auth behavior, tests, and budgets.

For each adapter or tool: write one failing behavior test, observe the expected failure, implement the minimum, verify green, then refactor. Generated client stubs are not proof; test request/response parity against fixtures and an authorized sandbox.

The generated MCP must ship with its own concise `skill/SKILL.md`, setup metadata, secret-reference instructions, discovery examples, safety rules, and recovery behavior. A cold agent must not need the build history.

### 7. Verify and agent-test

Read [evaluation.md](references/evaluation.md) and run all applicable layers. Use `run_fixture_matrix.py` for the reproducible three-site protocol lane, `benchmark_mcp.py` for envelope/latency evidence, and `run_agent_eval.py` only with an actual external agent command:

```bash
WEBSITE_MCP_APPROVAL_KEY=... python scripts/run_fixture_matrix.py --output /tmp/fixture-matrix.json
python scripts/benchmark_mcp.py --matrix /tmp/fixture-matrix.json --output /tmp/benchmark.json
python scripts/run_agent_eval.py --help
```

| Layer | Required proof |
|---|---|
| Unit | classification, auth injection/redaction/refresh, transforms, pagination, batching, graph traversal |
| Contract | OpenAPI validation plus stub/request/response parity |
| E2E | harmless read, CRUD sandbox, sequential flow, batch, upload/download, 401 recovery, rate limit |
| Performance | p50/p95, calls, bytes, tool-discovery tokens, response-envelope limits |
| Agent | cold discovery, correct execution, safe refusal/confirmation, recovery, budget compliance |

Run the same cold-agent tasks before promotion and after evidence-gated promotion. Capture tool calls, errors, tokens/bytes, latency, and outcome. “The tools list,” a scripted probe, or a fake-agent command is not an agent test.

### 8. Harden and hand off

Adversarially review authorization, secret handling, destructive writes, schema drift, retries, idempotency, rate limits, pagination, binary payloads, and misleading completion claims. Close gaps or record them in `coverage.json`.

Completion requires validated artifacts, green tests, benchmark evidence, a cold-read agent pass, setup from a clean checkout, and an explicit list of unsupported/UI-fallback capabilities. Keep local, packaged, published, installed, and live-tested states separate. If a deadline arrives with an external blocker, hand off a precisely labeled candidate such as “packaged; authorized E2E blocked by missing sandbox,” never a softened claim of completion.

## Stop conditions

Stop and ask for direction when authorization is ambiguous, a required login/secret reference is unavailable, the only apparent route requires bypassing controls, a destructive live test lacks a sandbox or explicit approval, or the target's terms prohibit the planned automation.

## Common failures

| Failure | Correction |
|---|---|
| Scaffold every possible adapter immediately | Prove representative tasks and contracts first |
| Mix verbs with capability types | Keep method, type, and surface separate |
| Expose one MCP tool per route | Use graph discovery plus intent-level native tools |
| Treat observed traffic as stable API | Record confidence and verify request/response parity |
| Put secrets/cookies in JSON evidence | Store references and redacted metadata only |
| Call passing unit tests “done” | Require E2E, performance, and cold-agent proof |
| Restart after context loss | Resume from validated stage artifacts |
