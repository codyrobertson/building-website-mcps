# Artifact contract

Read this before editing `.website-mcp`. These files are the handoff boundary between agents and stages.

## Contents

- [State](#statejson)
- [Authorization and auth](#authjson)
- [HTTP route map](#openapijson)
- [CLI contract](#clijson)
- [Action graph](#action-graphjson)
- [Evidence index](#evidence-indexjson)
- [Coverage](#coveragejson)
- [Specifications and decisions](#specmd-and-decisionsmd)

## `state.json`

Stages are `authorize`, `auth`, `discover`, `model`, `specify`, `implement`, `verify`, `agent-evaluate`, and `harden`. Status is `pending`, `in_progress`, `blocked`, or `complete`. The append-only hash-linked transition ledger is authoritative; the state snapshot is derived from it.

Dependency-satisfied independent workstreams may be in progress together (for example, auth and public discovery). Start/complete/reopen only with `transition_stage.py`; completed stages require evidence IDs, blocked stages require an exact unblock condition, and material discovery changes atomically reopen discovery/model and invalidate affected checkpoints.

## `auth.json`

Use `secret_policy: "references-only"`. A mode may contain:

```json
{
  "id": "oauth-user",
  "kind": "oauth",
  "secret_ref": "env:TARGET_REFRESH_TOKEN",
  "acquisition": "user-authorized device flow",
  "injection": "Authorization bearer header",
  "refresh": "refresh token before expiry",
  "expiry": "observed 3600 seconds",
  "redaction": ["authorization", "set-cookie"],
  "evidence": ["evidence/auth-read.json"],
  "confidence": "verified"
}
```

Kinds include `anonymous`, `api-key`, `bearer`, `oauth`, `service-account`, `cookie-session`, and `browser-session`. Acceptable session references include environment variables, OS keychain entries, secret-provider paths, and opaque browser-session handles. Never use secret-bearing keys such as `token`, `cookie`, `password`, `api_key`, or `secret`; use `secret_ref`.

## `openapi.json`

Use OpenAPI 3.1 for client-facing HTTP routes, including authenticated endpoints used by an authorized web client. Do not include pure UI gestures or local CLI commands. Every operation has `operationId`, request/response schemas, security, side-effect documentation, and:

```json
"x-mcp": {
  "route": "/v1/items/{id}",
  "type": "update",
  "surface": "hybrid"
}
```

The three core keys are stable and required:

- `route`: exact OpenAPI path.
- `type`: `auth`, `read`, `create`, `update`, `delete`, `action`, `upload`, or `download`.
- `surface`: `http` or `hybrid`. UI-only and STDIO capabilities belong in the graph/CLI contract, not OpenAPI.

HTTP method belongs in the path item operation key. Put provenance and confidence in a referenced graph node or a separate evidence index so the discovery triple stays compact.

Additional `x-*` fields are permitted. The validator rejects missing core keys, not useful namespaced metadata.

## `cli.json`

Record allowlisted local commands independently of OpenAPI. Each command includes `id`, executable reference, version evidence, arguments schema, stdout schema, stderr/exit-code behavior, side effects, auth/environment references, timeout, and evidence IDs. Never expose a free-form shell string as a generated MCP input.

## `action-graph.json`

Graph nodes represent agent-relevant capabilities, not raw screens. Example:

```json
{
  "id": "item.update",
  "intent": "Update an item",
  "surface": "hybrid",
  "operations": ["updateItem"],
  "native": "candidate",
  "execution": "independent",
  "auth": ["oauth-user"],
  "side_effect": "write",
  "confirmation": "when target is production",
  "evidence": ["evidence/network-item-update.json"],
  "confidence": "verified"
}
```

Allowed `execution` values: `independent`, `sequential`, `batch`, `paginated`, `upload-stream`, `download-stream`. Each node has one execution mode. Decompose composite workflows and connect nodes with `precedes`, `requires`, or `contains`. Native status: `no`, `candidate`, `yes`, `fallback`. `candidate` is discovery output and remains non-executable. A node may be `yes` only after its evidence includes the current exact promotion proof below, and it must have `confidence: "verified"`. Discovery, route maps, source code, browser observations, and immutable documentation can support modeling but cannot promote execution on their own.

Edges use `{ "from", "to", "kind" }`; kinds are `requires`, `produces`, `consumes`, `precedes`, `alternative`, or `contains`. Add `mapping` when an output field becomes a later input. Node IDs are unique and every edge endpoint must exist.

## `evidence-index.json`

Every route, auth claim, command, schema, or benchmark cites an evidence record. Each record includes `id`, `kind`, `source`, `captured_at`, `fresh_until` or `immutable: true`, `scope`, `redactions`, `redaction_verified`, `artifact`, and `sha256`. Stale evidence may guide discovery but cannot support a `verified` claim until refreshed. Dynamic auth, E2E, benchmark, cold-agent, and hardening records always require `fresh_until`; only timeless source/schema/documentation kinds may be immutable.

Promotion proof is deliberately stricter. It must be a non-immutable, hash-valid, unexpired record with `kind: "e2e"` or `kind: "contract"` and an exact binding for every adapter the capability exposes:

```json
{
  "id": "catalog-live-e2e",
  "kind": "e2e",
  "fresh_until": "2026-07-10T18:00:00Z",
  "artifact": "evidence/catalog-live-e2e.json",
  "sha256": "<sha256>",
  "promotion": {
    "bindings": [{
      "capability_id": "products.list",
      "operations": ["products.list"],
      "commands": []
    }]
  }
}
```

The binding arrays must exactly equal the graph node's `operations` and `commands`; a nearby endpoint or only one half of a hybrid capability is not proof. Record a redacted, reproducible E2E/contract result in the artifact, then run:

```bash
python scripts/promote_capabilities.py <project> products.list --evidence catalog-live-e2e
```

The promoter accepts only `native: "candidate"`, holds the workspace lock, validates the proposed graph and derived coverage in a temporary workspace, then atomically replaces the graph and coverage files. It fails closed on missing, stale, hash-invalid, unsafe, discovery-only, or irrelevant proof.

To make an operator-owned E2E command reproducible without hand-writing a proof artifact, use `record_e2e_proof.py`. It accepts exactly one JSON argv source (inline or a bounded JSON file), never invokes a shell, requires a successful exit, and records only command/output digests, byte counts, duration, and exit metadata. It rejects secret-bearing output and does not claim that a passing command proves more than that command's execution. The operator remains responsible for choosing a real E2E/contract command and declaring the exact graph binding it exercises:

```bash
python scripts/record_e2e_proof.py <project> products.list \
  --evidence-id catalog-list-e2e \
  --operations-json '["products.list"]' \
  --commands-json '[]' \
  --argv-file ./catalog-list-e2e.argv.json
python scripts/promote_capabilities.py <project> products.list --evidence catalog-list-e2e
```

## `coverage.json`

Track observed, modeled, and verified route counts; observed, native, and verified action counts; and explicit gaps. A gap includes impact, evidence, workaround, owner, and disposition. Never turn missing evidence into a zero-gap claim.

## `spec.md` and `decisions.md`

`spec.md` contains authorized scope, forbidden actions, representative agent tasks, safety requirements, and numeric budgets. `decisions.md` is append-only: date, decision, evidence, confidence, alternatives, and reversal condition.
