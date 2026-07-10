# CLI-only MCP Implementation Plan

> **Required execution skill:** Use `superpowers:test-driven-development` task-by-task.

**Goal:** Make `cli://local` a credential-free, contract-driven MCP target without any HTTP crawl, while preserving HTTP and hybrid discovery.

**Architecture:** The scaffold validates `cli://` targets and records an empty OpenAPI shell. Discovery branches before HTTP observation, requires a safe explicit CLI contract, captures the contract as evidence, and uses it to produce candidate STDIO graph nodes and coverage. The existing promotion and generator path then promote and execute the allowlisted commands through the existing shell-free adapter.

**Tech Stack:** Python 3.10 standard library, unittest, newline-delimited JSON-RPC MCP.

---

### Task 1: Prove target/contract gating

**Files:**
- Modify: `building-website-mcps/tests/test_discovery.py`
- Modify: `building-website-mcps/scripts/scaffold_workspace.py`
- Modify: `building-website-mcps/scripts/discover_target.py`

1. Write tests that `cli://local` scaffolds, rejects userinfo/raw paths, and discovery rejects absent or unsafe contracts without touching HTTP.
2. Run the tests and observe the expected failures.
3. Add target classification and CLI-specific argument validation.
4. Run the tests green.

### Task 2: Compile CLI-only discovery candidates

**Files:**
- Modify: `building-website-mcps/tests/test_discovery.py`
- Modify: `building-website-mcps/scripts/site_to_mcp/compiler.py`

1. Write a test that CLI-only discovery emits an empty OpenAPI 3.1 document, contract evidence, candidate STDIO nodes, CLI coverage, and checkpoints.
2. Run it red.
3. Add a CLI-only compile path that reuses the strict allowlisted contract normalization and avoids `observe`.
4. Run it green.

### Task 3: Prove promotion, generation, and STDIO execution

**Files:**
- Modify: `building-website-mcps/tests/test_generated_mcp.py`
- Modify: `building-website-mcps/SKILL.md`

1. Write an end-to-end test that records command proof, promotes a CLI-only candidate, generates a server, and executes it over STDIO.
2. Run it red.
3. Make only integration adjustments needed for the existing generator and CLI adapter to consume the generated CLI-only artifacts.
4. Run it green and document the exact local CLI command.

### Task 4: Verify regression boundaries

**Files:**
- Test: `building-website-mcps/tests/test_discovery.py`
- Test: `building-website-mcps/tests/test_generated_mcp.py`
- Test: `building-website-mcps/tests/test_promotion.py`

1. Run targeted tests, then the full unittest discovery suite.
2. Inspect generated artifacts with the workspace validator.
3. Report explicit evidence for CLI-only behavior and unchanged hybrid behavior.
