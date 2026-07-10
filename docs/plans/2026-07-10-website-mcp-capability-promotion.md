# Capability Promotion Gate Implementation Plan

> **Required execution skill:** Use `superpowers:executing-plans` to implement this plan task-by-task.

**Goal:** Allow a Website MCP capability to become executable only after current, hash-checked end-to-end or contract evidence proves its exact HTTP and/or CLI bindings.

**Architecture:** `evidence-index.json` records an explicit `promotion.bindings` mapping from a capability ID to its complete operation and command bindings. The validator rejects any `native: "yes"` node without a current, hash-valid `e2e` or `contract` record for that exact binding. `promote_capabilities.py` checks all preconditions while holding a workspace lock, changes graph and derived coverage through atomic file replacements, and does not modify the workspace when proof is missing, stale, unrelated, or unsafe.

**Tech Stack:** Python 3.10 standard library, JSON, SHA-256, `fcntl`/`msvcrt` locking, `unittest`, bundled HTTP and CLI fixtures.

---

### Task 1: Specify the fail-closed validator contract

**Files:**

- Modify: `building-website-mcps/scripts/validate_workspace.py`
- Modify: `building-website-mcps/references/artifact-contract.md`
- Test: `building-website-mcps/tests/test_promotion.py`

1. Write a fixture-based failing test that marks a candidate as promoted with discovery-only evidence and expects build validation to refuse it.
2. Run `python -m unittest building-website-mcps.tests.test_promotion.CapabilityPromotionTest.test_discovery_evidence_cannot_promote -v` and confirm it fails because the gate is not implemented.
3. Add a promotion-evidence predicate requiring a fresh, hash-valid `e2e` or `contract` record whose complete binding exactly matches the graph node.
4. Re-run the focused test and confirm it passes.

### Task 2: Promote one candidate safely

**Files:**

- Create: `building-website-mcps/scripts/promote_capabilities.py`
- Modify: `building-website-mcps/scripts/validate_workspace.py`
- Test: `building-website-mcps/tests/test_promotion.py`

1. Write failing tests for missing, stale, altered-hash, wrong-capability, and discovery evidence; assert graph and coverage bytes remain unchanged after each refusal.
2. Run the focused tests and confirm the missing command/module failure.
3. Implement a lock-scoped promotion command which validates the candidate and supplied proof, derives coverage from the changed graph, and atomically replaces both JSON files only after the complete in-memory result validates.
4. Re-run the focused tests and confirm every refusal preserves bytes and the valid promotion becomes `native: "yes"`, `confidence: "verified"`.

### Task 3: Prove all supported surfaces and generated execution

**Files:**

- Modify: `building-website-mcps/tests/test_promotion.py`
- Modify: `building-website-mcps/tests/test_generated_mcp.py`
- Modify: `building-website-mcps/SKILL.md`

1. Write one failing end-to-end test using real subprocess fixture sites to record: public catalog list/manual, authenticated session read/write, and hybrid CLI inspect/render verification.
2. Run that test and confirm the candidates remain non-executable before promotion.
3. Record fresh fixtures as exact promotion evidence, invoke the promotion command, generate the MCP package, and prove `execute_capability` performs each promoted binding.
4. Re-run the promotion and generated-MCP tests, then the full `unittest` suite.

### Task 4: Record reproducible operator E2E proof

**Files:**

- Create: `building-website-mcps/scripts/record_e2e_proof.py`
- Modify: `building-website-mcps/tests/test_promotion.py`
- Modify: `building-website-mcps/{SKILL.md,references/artifact-contract.md}`

1. Write failing tests for a successful explicit argv proof, exact binding, promotion handoff, and unbound/shell/nonzero/timeout/secret-output refusal.
2. Run the focused tests and confirm they fail while the recorder is absent.
3. Implement a lock-scoped recorder that accepts only argv JSON or a bounded argv JSON file, runs `shell=False`, writes digest-only redacted execution metadata, and appends a fresh exact E2E record.
4. Verify the focused tests and full suite; document that successful command execution is not a semantic claim about an arbitrary test.
