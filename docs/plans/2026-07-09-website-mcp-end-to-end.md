# Website-to-MCP End-to-End Implementation Plan

> **Required execution skill:** Use `superpowers:subagent-driven-development` where repository isolation exists; in this non-git workspace use `sedona-dev:implementation-swarm` with one writer and independent reviewers.

**Goal:** Turn `building-website-mcps` into a safe, iterative compiler that discovers runnable websites, generates standalone MCP servers and companion skills, and proves them across three live fixture sites.

**Architecture:** Python 3.10 stdlib scripts maintain evidence-backed discovery state, normalize OpenAPI/HTML/CLI contracts, and emit a standalone newline-delimited JSON-RPC MCP package. Three independent local HTTP applications provide stable real-network proof for anonymous HTTP, cookie+CSRF workflows, and hybrid CLI behavior. Validation has structure, build, and release levels so drafts remain usable while false completion is impossible.

**Tech Stack:** Python 3.10 stdlib, `unittest`, `ThreadingHTTPServer`, `urllib`, `subprocess`, JSON-RPC over STDIO.

---

### Task 1: Safe resumable state and semantic validator

**Files:**
- Modify: `building-website-mcps/scripts/scaffold_workspace.py`
- Create: `building-website-mcps/scripts/transition_stage.py`
- Create: `building-website-mcps/scripts/scan_secrets.py`
- Modify: `building-website-mcps/scripts/validate_workspace.py`
- Modify: `building-website-mcps/tests/test_workspace_tools.py`

1. Add failing tests proving rerunning scaffold cannot change bytes or mtimes; `--repair` only creates missing files; `--force` creates a verified backup.
2. Run the focused tests and confirm failures describe destructive overwrite.
3. Implement create-only preflight, repair, force/backup, target mismatch, and symlink refusal.
4. Add failing tests for legal transition history, evidence-required completion, dependency-satisfied parallel stages, reopen, and blocked reasons.
5. Implement append-only hash-linked transitions and snapshot reconciliation.
6. Add failing tests for null/dangling graph data, operation/evidence/auth references, hashes, coverage reconciliation, recursive secret leaks, and structure/build/release levels.
7. Implement semantic validation and secret scanning, allowing reference URIs and schema property declarations while rejecting actual values without echoing them.
8. Run `python -m unittest building-website-mcps.tests.test_workspace_tools -v` and require all tests green.

### Task 2: Iterative discovery compiler

**Files:**
- Create: `building-website-mcps/scripts/discover_target.py`
- Create: `building-website-mcps/scripts/approve_checkpoint.py`
- Create: `building-website-mcps/scripts/site_to_mcp/{__init__.py,discovery.py,model.py,evidence.py}`
- Create: `building-website-mcps/tests/test_discovery.py`

1. Write failing tests for same-origin OpenAPI probing, HTML forms/links, local CLI manifest ingestion, redacted evidence hashes, and unsupported-contract coverage gaps.
2. Implement conservative OpenAPI 3.1 subset normalization and HTML discovery without guessing unsupported serialization.
3. Write failing tests requiring a closed hypothesis-observation-model loop and scope/native-floor/final checkpoints before build/release.
4. Implement `discovery-iterations.jsonl` and `checkpoints.jsonl`; material new evidence invalidates the prior native-floor checkpoint and reopens discovery/model.
5. Verify discovery tests and ensure credentialed/live-write scopes cannot auto-approve safety checkpoints.

### Task 3: Three runnable fixture sites

**Files:**
- Create: `building-website-mcps/fixtures/common.py`
- Create: `building-website-mcps/fixtures/public_catalog/{app.py,openapi.json}`
- Create: `building-website-mcps/fixtures/session_admin/{app.py,openapi.json,data/valid.csv,data/invalid.csv}`
- Create: `building-website-mcps/fixtures/hybrid_cli/{app.py,partial-openapi.json,fixture_cli.py,cli-contract.json}`
- Create: `building-website-mcps/tests/fixture_harness.py`
- Create: `building-website-mcps/tests/test_fixture_sites.py`

1. Write failing HTTP-process tests for readiness, real routes, hidden fixture controls, state changes, auth, CSRF, rate limiting, files, and safe CLI argv.
2. Implement three independent `ThreadingHTTPServer` sites binding `127.0.0.1:0` and emitting readiness JSON.
3. Public catalog covers pagination, projection, detail, and binary manual download.
4. Session admin covers login cookie, CSRF, CRUD, ETag/idempotency, bounded batch, CSV preview/commit/error download, 401, and 429 controls.
5. Hybrid fixture covers partial OpenAPI plus HTML-discovered events and allowlisted inspect/render/verify CLI operations.
6. Run fixture tests through real HTTP and subprocesses, never direct imports as E2E proof.

### Task 4: Standalone MCP generator and runtime

**Files:**
- Create: `building-website-mcps/assets/python-mcp/server.py`
- Create: `building-website-mcps/assets/python-mcp/website_mcp/{protocol.py,catalog.py,http_adapter.py,auth.py,cli_adapter.py,executor.py}`
- Create: `building-website-mcps/scripts/generate_mcp.py`
- Create: `building-website-mcps/scripts/mcp_probe.py`
- Create: `building-website-mcps/tests/test_generated_mcp.py`

1. Write failing subprocess tests for `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`, malformed JSON-RPC, clean EOF, and stdout protocol purity.
2. Implement a standalone newline-delimited JSON-RPC runtime with three compact discovery tools and promoted intent-level tools.
3. Write failing tests for path/query/JSON requests, bounded pagination/batch, file upload/download checksums, cookie+CSRF reauth, idempotent retry rules, and CLI `shell=False` allowlists.
4. Implement adapters and generated runtime config containing references only.
5. Generate a companion `skill/SKILL.md` containing setup, secret refs, discovery examples, confirmations, recovery, and coverage gaps.
6. Prove a clean generated directory launches without importing the builder repository.

### Task 5: Full fixture matrix, performance, and agent evaluation

**Files:**
- Create: `building-website-mcps/scripts/run_fixture_matrix.py`
- Create: `building-website-mcps/scripts/benchmark_mcp.py`
- Create: `building-website-mcps/scripts/run_agent_eval.py`
- Create: `building-website-mcps/tests/test_fixture_matrix_e2e.py`
- Create: `building-website-mcps/tests/test_performance.py`

1. Write failing E2E tests for start site → discover → checkpoint approval → validate build → generate → STDIO initialize/list/call → verify HTTP/filesystem effect → release validation.
2. Implement the matrix for all three fixtures and store machine-readable traces.
3. Enforce tools/list ≤16 KiB, search ≤4 KiB, normal read ≤8 KiB, batch ≤16 KiB, no base64 payloads, and local latency budgets with an environment multiplier.
4. Implement a configurable agent-eval runner that records prompt, MCP config, tool trace, latency, bytes, outcome, and redacted stdout/stderr.
5. Run three independent cold agents for ambiguous read, confirmed multi-step write, and expired-auth recovery. Treat deterministic probes as protocol tests, never agent tests.

### Task 6: Skill workflow, review, and release proof

**Files:**
- Modify: `building-website-mcps/SKILL.md`
- Modify: `building-website-mcps/references/{artifact-contract.md,architecture.md,evaluation.md}`
- Modify: `building-website-mcps/agents/openai.yaml`

1. Update the skill to use adaptive `simple`/`full` profiles, dependency-gated workstreams, explicit discovery loops, and user checkpoints.
2. Remove STDIO from auth kinds and make `x-mcp` require a core subset while allowing extensions.
3. Document exact builder commands and generated outputs.
4. Run the entire unittest suite, fixture matrix, benchmarks, secret scan, skill validation, and clean MCP probes.
5. Request spec review, code-quality review, and final adversarial review; fix all blockers and rerun affected checks.
6. Run Ultracode doctor `--final`, render the handoff, and close the goal only when all required evidence exists.
