import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
APPROVAL_KEY = "website-mcp-test-approval-key"
os.environ.setdefault("WEBSITE_MCP_APPROVAL_KEY", APPROVAL_KEY)
SCAFFOLD = SKILL_ROOT / "scripts" / "scaffold_workspace.py"
TRANSITION = SKILL_ROOT / "scripts" / "transition_stage.py"
VALIDATE = SKILL_ROOT / "scripts" / "validate_workspace.py"
APPROVE = SKILL_ROOT / "scripts" / "approve_checkpoint.py"
DISCOVER = SKILL_ROOT / "scripts" / "discover_target.py"


def run(*args: object, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *(str(arg) for arg in args)],
        capture_output=True,
        text=True,
        timeout=10,
        env=env or dict(os.environ),
    )


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def tree_hashes(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file()
    }


class WorkspaceToolsTest(unittest.TestCase):
    def scaffold(self, tmp: str, target: str = "https://example.test") -> Path:
        result = run(SCAFFOLD, tmp, target)
        self.assertEqual(result.returncode, 0, result.stderr)
        return Path(tmp) / ".website-mcp"

    def validate(self, tmp: str, level: str = "structure") -> subprocess.CompletedProcess[str]:
        return run(VALIDATE, tmp, "--level", level)

    def add_evidence(
        self,
        root: Path,
        evidence_id: str,
        body: bytes = b"proof",
        *,
        kind: str = "test",
        scope: str = "test",
        immutable: bool = True,
        fresh_until: str | None = None,
    ) -> None:
        evidence_dir = root / "evidence"
        evidence_dir.mkdir(exist_ok=True)
        artifact = evidence_dir / f"{evidence_id}.txt"
        artifact.write_bytes(body)
        index = read_json(root / "evidence-index.json")
        record = {
                "id": evidence_id,
                "kind": kind,
                "source": "fixture",
                "captured_at": "2026-07-09T00:00:00Z",
                "scope": scope,
                "redactions": [],
                "redaction_verified": True,
                "artifact": f"evidence/{evidence_id}.txt",
                "sha256": hashlib.sha256(body).hexdigest(),
            }
        if immutable:
            record["immutable"] = True
        if fresh_until is not None:
            record["fresh_until"] = fresh_until
        index["records"].append(record)
        write_json(root / "evidence-index.json", index)

    def make_release_workspace(self, tmp: str) -> Path:
        root = self.scaffold(tmp)
        proofs = {
            "scope": ("authorization", "authorized-scope"),
            "auth": ("auth-proof", "auth"),
            "routes": ("route-discovery", "discovery"),
            "model": ("model-proof", "model"),
            "spec": ("specification", "specification"),
            "implementation": ("implementation", "implementation"),
            "e2e": ("e2e", "e2e"),
            "benchmark": ("benchmark", "performance"),
            "agent": ("cold-agent", "agent-evaluation"),
            "harden": ("hardening", "hardening"),
        }
        for evidence_id, (kind, scope) in proofs.items():
            dynamic = kind in {"auth-proof", "e2e", "benchmark", "cold-agent", "hardening"}
            self.add_evidence(
                root,
                evidence_id,
                kind=kind,
                scope=scope,
                immutable=not dynamic,
                fresh_until="2099-01-01T00:00:00Z" if dynamic else None,
            )
        auth = read_json(root / "auth.json")
        auth["status"] = "anonymous"
        auth["evidence"] = ["auth"]
        auth["modes"] = [{"id": "anonymous", "kind": "anonymous", "evidence": ["auth"]}]
        write_json(root / "auth.json", auth)
        openapi = read_json(root / "openapi.json")
        openapi["paths"] = {
            "/items": {
                "get": {
                    "operationId": "items.list",
                    "security": [],
                    "responses": {"200": {"description": "ok"}},
                    "x-mcp": {
                        "route": "/items",
                        "type": "read",
                        "surface": "http",
                        "evidence": ["routes"],
                    },
                }
            }
        }
        write_json(root / "openapi.json", openapi)
        graph = read_json(root / "action-graph.json")
        graph["nodes"] = [
            {
                "id": "items.list",
                "intent": "List items",
                "surface": "http",
                "operations": ["items.list"],
                "native": "yes",
                "execution": "independent",
                "auth": ["anonymous"],
                "side_effect": "read",
                "confirmation": "none",
                "evidence": ["routes", "e2e"],
                "confidence": "verified",
            }
        ]
        write_json(root / "action-graph.json", graph)
        evidence_index = read_json(root / "evidence-index.json")
        e2e_record = next(record for record in evidence_index["records"] if record["id"] == "e2e")
        e2e_record["promotion"] = {
            "bindings": [
                {
                    "capability_id": "items.list",
                    "operations": ["items.list"],
                    "commands": [],
                }
            ]
        }
        write_json(root / "evidence-index.json", evidence_index)
        coverage = read_json(root / "coverage.json")
        coverage["route_counts"] = {"observed": 1, "modeled": 1, "verified": 1}
        coverage["action_counts"] = {"observed": 1, "native": 1, "verified": 1}
        write_json(root / "coverage.json", coverage)
        stage_proofs = {
            "authorize": ["scope"],
            "auth": ["auth"],
            "discover": ["routes"],
            "model": ["model"],
            "specify": ["spec"],
            "implement": ["implementation"],
            "verify": ["e2e", "benchmark"],
            "agent-evaluate": ["agent"],
            "harden": ["harden"],
        }
        for stage, evidence in stage_proofs.items():
            state = read_json(root / "state.json")
            status = next(item["status"] for item in state["stages"] if item["id"] == stage)
            if status == "pending":
                self.assertEqual(run(TRANSITION, tmp, stage, "in_progress").returncode, 0)
            result = run(TRANSITION, tmp, stage, "complete", "--evidence", *evidence)
            self.assertEqual(result.returncode, 0, result.stderr)
        return root

    def test_scaffold_is_create_only_and_refusal_does_not_mutate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            (root / "decisions.md").write_text("important decision\n", encoding="utf-8")
            before = tree_hashes(root)

            repeated = run(SCAFFOLD, tmp, "https://example.test")

            self.assertEqual(repeated.returncode, 2)
            self.assertIn("already exists", repeated.stderr)
            self.assertEqual(tree_hashes(root), before)
            self.assertEqual(
                (root / "decisions.md").read_text(encoding="utf-8"),
                "important decision\n",
            )

    def test_repair_creates_only_missing_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            (root / "decisions.md").write_text("keep me\n", encoding="utf-8")
            (root / "cli.json").unlink()
            before = tree_hashes(root)
            before.pop("cli.json", None)

            repaired = run(SCAFFOLD, tmp, "https://example.test", "--repair")

            self.assertEqual(repaired.returncode, 0, repaired.stderr)
            self.assertTrue((root / "cli.json").is_file())
            after = tree_hashes(root)
            after.pop("cli.json")
            self.assertEqual(after, before)

    def test_force_backs_up_then_replaces_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            (root / "decisions.md").write_text("old decision\n", encoding="utf-8")
            before = tree_hashes(root)

            forced = run(SCAFFOLD, tmp, "https://other.test", "--force")

            self.assertEqual(forced.returncode, 0, forced.stderr)
            self.assertEqual(read_json(root / "state.json")["target"], "https://other.test")
            backups = list((Path(tmp) / ".website-mcp.backups").iterdir())
            self.assertEqual(len(backups), 1)
            backup_hashes = tree_hashes(backups[0])
            backup_hashes.pop("backup-manifest.json")
            self.assertEqual(backup_hashes, before)

    def test_repair_refuses_target_mismatch_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            mismatch = run(SCAFFOLD, tmp, "https://other.test", "--repair")
            self.assertEqual(mismatch.returncode, 2)
            self.assertEqual(read_json(root / "state.json")["target"], "https://example.test")

            target = Path(tmp) / "outside.json"
            target.write_text("{}", encoding="utf-8")
            (root / "cli.json").unlink()
            os.symlink(target, root / "cli.json")
            linked = run(SCAFFOLD, tmp, "https://example.test", "--repair")
            self.assertEqual(linked.returncode, 2)
            self.assertIn("symlink", linked.stderr)

    def test_transition_supports_evidence_gates_blocking_reopen_and_parallel_discovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            self.add_evidence(root, "scope")
            complete = run(
                TRANSITION, tmp, "authorize", "complete", "--evidence", "scope"
            )
            self.assertEqual(complete.returncode, 0, complete.stderr)

            auth = run(TRANSITION, tmp, "auth", "in_progress")
            discover = run(TRANSITION, tmp, "discover", "in_progress")
            self.assertEqual(auth.returncode, 0, auth.stderr)
            self.assertEqual(discover.returncode, 0, discover.stderr)

            no_evidence = run(TRANSITION, tmp, "discover", "complete")
            self.assertEqual(no_evidence.returncode, 2)
            blocked = run(TRANSITION, tmp, "discover", "blocked")
            self.assertEqual(blocked.returncode, 2)
            blocked = run(
                TRANSITION,
                tmp,
                "discover",
                "blocked",
                "--reason",
                "fixture unavailable",
            )
            self.assertEqual(blocked.returncode, 0, blocked.stderr)
            resumed = run(
                TRANSITION,
                tmp,
                "discover",
                "in_progress",
                "--reason",
                "fixture restored",
            )
            self.assertEqual(resumed.returncode, 0, resumed.stderr)

            self.add_evidence(root, "routes")
            done = run(TRANSITION, tmp, "discover", "complete", "--evidence", "routes")
            self.assertEqual(done.returncode, 0, done.stderr)
            reopened = run(TRANSITION, tmp, "discover", "in_progress")
            self.assertEqual(reopened.returncode, 2)
            reopened = run(
                TRANSITION,
                tmp,
                "discover",
                "in_progress",
                "--reason",
                "new route evidence",
            )
            self.assertEqual(reopened.returncode, 0, reopened.stderr)
            state = read_json(root / "state.json")
            self.assertGreaterEqual(state["stages"][2]["iteration"], 2)
            self.assertTrue(state["history"][-1]["hash"])

    def test_transition_atomically_invalidates_completed_discovery_and_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            for evidence_id in ("scope", "routes", "model", "changed-routes"):
                self.add_evidence(root, evidence_id)
            self.assertEqual(
                run(TRANSITION, tmp, "authorize", "complete", "--evidence", "scope").returncode,
                0,
            )
            for stage, evidence_id in (("discover", "routes"), ("model", "model")):
                self.assertEqual(run(TRANSITION, tmp, stage, "in_progress").returncode, 0)
                self.assertEqual(
                    run(TRANSITION, tmp, stage, "complete", "--evidence", evidence_id).returncode,
                    0,
                )

            invalidated = run(
                TRANSITION,
                tmp,
                "discover",
                "invalidate",
                "--evidence",
                "changed-routes",
                "--reason",
                "material route evidence changed",
            )
            self.assertEqual(invalidated.returncode, 0, invalidated.stderr)
            state = read_json(root / "state.json")
            stages = {stage["id"]: stage for stage in state["stages"]}
            self.assertEqual(stages["discover"]["status"], "in_progress")
            self.assertEqual(stages["model"]["status"], "in_progress")
            self.assertEqual(stages["discover"]["iteration"], 2)
            self.assertEqual(stages["model"]["iteration"], 2)
            self.assertEqual(state["history"][-1]["kind"], "cascade-invalidate")
            self.assertEqual(run(VALIDATE, tmp).returncode, 0)

    def test_validator_accepts_x_mcp_extensions_but_rejects_null_graph_and_dangling_refs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            openapi = read_json(root / "openapi.json")
            openapi["paths"] = {
                "/items": {
                    "get": {
                        "operationId": "listItems",
                        "responses": {"200": {"description": "ok"}},
                        "x-mcp": {
                            "route": "/items",
                            "type": "read",
                            "surface": "http",
                            "x-confidence": "observed",
                        },
                    }
                }
            }
            write_json(root / "openapi.json", openapi)
            valid_extension = self.validate(tmp)
            self.assertEqual(valid_extension.returncode, 0, valid_extension.stderr)

            graph = read_json(root / "action-graph.json")
            graph["nodes"] = [{"id": None, "operations": ["missingOperation"], "evidence": ["missing"]}]
            write_json(root / "action-graph.json", graph)
            invalid = self.validate(tmp)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("non-empty string", invalid.stderr)
            self.assertIn("unknown operationId", invalid.stderr)
            self.assertIn("unknown evidence", invalid.stderr)

    def test_validator_checks_evidence_hash_and_derived_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            self.add_evidence(root, "route-proof")
            index = read_json(root / "evidence-index.json")
            index["records"][0]["sha256"] = "0" * 64
            write_json(root / "evidence-index.json", index)
            bad_hash = self.validate(tmp, "build")
            self.assertNotEqual(bad_hash.returncode, 0)
            self.assertIn("sha256 does not match", bad_hash.stderr)

            index["records"][0]["sha256"] = hashlib.sha256(b"proof").hexdigest()
            write_json(root / "evidence-index.json", index)
            coverage = read_json(root / "coverage.json")
            coverage["route_counts"]["modeled"] = 5
            write_json(root / "coverage.json", coverage)
            lie = self.validate(tmp, "build")
            self.assertNotEqual(lie.returncode, 0)
            self.assertIn("does not match derived", lie.stderr)

    def test_validator_rejects_all_complete_without_evidence_and_history_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            state = read_json(root / "state.json")
            for stage in state["stages"]:
                stage["status"] = "complete"
                stage["evidence"] = []
            state["history"][0]["hash"] = "f" * 64
            write_json(root / "state.json", state)

            invalid = self.validate(tmp, "build")
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("complete requires evidence", invalid.stderr)
            self.assertIn("history hash", invalid.stderr)

    def test_contextual_secret_scan_rejects_nested_values_and_allows_references_and_schema_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            auth = read_json(root / "auth.json")
            auth["modes"] = [
                {
                    "id": "oauth",
                    "kind": "oauth",
                    "secret_ref": "env:TARGET_REFRESH_TOKEN",
                    "metadata": {"sha256": "a" * 64},
                }
            ]
            write_json(root / "auth.json", auth)
            openapi = read_json(root / "openapi.json")
            openapi["components"] = {
                "schemas": {
                    "Login": {
                        "type": "object",
                        "properties": {"password": {"type": "string"}},
                    }
                }
            }
            write_json(root / "openapi.json", openapi)
            safe = self.validate(tmp)
            self.assertEqual(safe.returncode, 0, safe.stderr)

            openapi["components"]["schemas"]["Login"]["properties"]["password"]["default"] = "hunter2"
            write_json(root / "openapi.json", openapi)
            schema_leak = self.validate(tmp)
            self.assertNotEqual(schema_leak.returncode, 0)
            self.assertIn("secret-bearing schema example", schema_leak.stderr)
            del openapi["components"]["schemas"]["Login"]["properties"]["password"]["default"]
            write_json(root / "openapi.json", openapi)

            auth["modes"][0]["headers"] = {"Authorization": "Bearer raw-secret-value"}
            write_json(root / "auth.json", auth)
            leaked = self.validate(tmp)
            self.assertNotEqual(leaked.returncode, 0)
            self.assertIn("secret-bearing value", leaked.stderr)
            self.assertNotIn("raw-secret-value", leaked.stderr)

            auth["modes"][0].pop("headers")
            auth["modes"][0]["secret_ref"] = "this-is-the-secret"
            write_json(root / "auth.json", auth)
            bad_ref = self.validate(tmp)
            self.assertNotEqual(bad_ref.returncode, 0)
            self.assertIn("invalid secret reference", bad_ref.stderr)

    def test_scanner_rejects_nested_sensitive_aliases_in_body_and_url_query(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "capture.json").write_text(
                json.dumps(
                    {
                        "body": json.dumps({"nested": {"user_session_id": "raw-session"}}),
                        "url": "https://example.test/callback?user_api_key=raw-api-key",
                    }
                ),
                encoding="utf-8",
            )
            invalid = self.validate(tmp)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("user_session_id", invalid.stderr)
            self.assertIn("user_api_key", invalid.stderr)

    def test_checkpoint_jsonl_symlink_is_refused_without_external_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, "http://127.0.0.1:9876")
            outside = Path(tmp) / "outside-checkpoints.jsonl"
            outside.write_text("", encoding="utf-8")
            (root / "checkpoints.jsonl").unlink()
            os.symlink(outside, root / "checkpoints.jsonl")
            blocked = run(
                APPROVE,
                tmp,
                "scope",
                "--decision",
                "approve",
                "--artifact",
                "spec.md",
                "--actor",
                "fixture-test",
                "--fixture-test",
            )
            self.assertEqual(blocked.returncode, 2)
            self.assertEqual(outside.read_text(encoding="utf-8"), "")

    def test_jsonl_rejects_non_object_corruption_for_append_and_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, "http://127.0.0.1:9876")
            (root / "checkpoints.jsonl").write_text("[]\n", encoding="utf-8")
            rejected = run(
                APPROVE,
                tmp,
                "scope",
                "--decision",
                "approve",
                "--artifact",
                "spec.md",
                "--actor",
                f"local-uid:{os.getuid()}",
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("JSONL", rejected.stderr)

        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            (root / "discovery-iterations.jsonl").write_text("[]\n", encoding="utf-8")
            invalid = self.validate(tmp)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertNotIn("Traceback", invalid.stderr)
            self.assertIn("discovery-iterations", invalid.stderr)

    def test_scanner_rejects_camelcase_javascript_and_html_secret_assignments(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "page.html").write_text(
                '<script>const clientSecret = "raw-client-secret"; sessionId="raw-session";</script>\n'
                '<input api_key_value="raw-api-key">\n',
                encoding="utf-8",
            )
            invalid = self.validate(tmp)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("clientSecret", invalid.stderr)
            self.assertIn("sessionId", invalid.stderr)
            self.assertIn("api_key_value", invalid.stderr)

    def test_scanner_rejects_quoted_identifier_assignments_with_spaces_and_escapes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "page.html").write_text(
                '<script>const clientSecret = "raw client \\"secret\\""; '
                "let sessionId = 'raw session id';</script>\n",
                encoding="utf-8",
            )
            invalid = self.validate(tmp)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("clientSecret", invalid.stderr)
            self.assertIn("sessionId", invalid.stderr)

    def test_stdio_is_not_an_auth_kind(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            auth = read_json(root / "auth.json")
            auth["modes"] = [{"id": "local", "kind": "stdio"}]
            write_json(root / "auth.json", auth)
            invalid = self.validate(tmp)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("auth kind", invalid.stderr)

    def test_cli_executable_reference_is_not_mistaken_for_secret_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            self.add_evidence(root, "cli-proof")
            cli = read_json(root / "cli.json")
            cli["commands"] = [
                {
                    "id": "items.list",
                    "executable_ref": "fixture-cli",
                    "version_evidence": "cli-proof",
                    "arguments_schema": {"type": "object"},
                    "stdout_schema": {"type": "object"},
                    "exit_codes": {"0": "success"},
                    "side_effect": "read",
                    "timeout_ms": 1000,
                    "evidence": ["cli-proof"],
                }
            ]
            write_json(root / "cli.json", cli)
            valid = self.validate(tmp)
            self.assertEqual(valid.returncode, 0, valid.stderr)

    def test_protected_discovery_cannot_complete_while_auth_is_in_progress(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            self.add_evidence(root, "scope")
            self.add_evidence(root, "routes")
            self.assertEqual(
                run(TRANSITION, tmp, "authorize", "complete", "--evidence", "scope").returncode,
                0,
            )
            self.assertEqual(run(TRANSITION, tmp, "auth", "in_progress").returncode, 0)
            self.assertEqual(run(TRANSITION, tmp, "discover", "in_progress").returncode, 0)
            self.assertEqual(
                run(TRANSITION, tmp, "discover", "complete", "--evidence", "routes").returncode,
                0,
            )
            openapi = read_json(root / "openapi.json")
            openapi["paths"] = {
                "/me": {
                    "get": {
                        "operationId": "getMe",
                        "security": [{"oauth": []}],
                        "responses": {"200": {"description": "ok"}},
                        "x-mcp": {"route": "/me", "type": "read", "surface": "http"},
                    }
                }
            }
            write_json(root / "openapi.json", openapi)

            invalid = self.validate(tmp)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("protected discovery", invalid.stderr)

    def test_transition_rejects_bad_evidence_hash_and_tampered_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            self.add_evidence(root, "scope")
            (root / "evidence" / "scope.txt").write_bytes(b"changed")
            bad_evidence = run(
                TRANSITION, tmp, "authorize", "complete", "--evidence", "scope"
            )
            self.assertEqual(bad_evidence.returncode, 2)
            self.assertIn("evidence hash", bad_evidence.stderr)

            (root / "evidence" / "scope.txt").write_bytes(b"proof")
            state = read_json(root / "state.json")
            state["history"][0]["hash"] = "f" * 64
            write_json(root / "state.json", state)
            tampered = run(
                TRANSITION, tmp, "authorize", "complete", "--evidence", "scope"
            )
            self.assertEqual(tampered.returncode, 2)
            self.assertIn("history", tampered.stderr)

    def test_build_rejects_empty_workspace_and_release_rejects_generic_proof_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            empty = self.validate(tmp, "build")
            self.assertNotEqual(empty.returncode, 0)
            self.assertIn("build requires at least one modeled capability", empty.stderr)

            self.add_evidence(root, "generic")
            for stage in ["authorize", "auth", "discover", "model", "specify", "implement", "verify", "agent-evaluate", "harden"]:
                state = read_json(root / "state.json")
                current = next(item["status"] for item in state["stages"] if item["id"] == stage)
                if current == "pending":
                    self.assertEqual(run(TRANSITION, tmp, stage, "in_progress").returncode, 0)
                self.assertEqual(
                    run(TRANSITION, tmp, stage, "complete", "--evidence", "generic").returncode,
                    0,
                )
            release = self.validate(tmp, "release")
            self.assertNotEqual(release.returncode, 0)
            self.assertIn("release requires capability evidence", release.stderr)

    def test_upstream_reopen_rejects_non_pending_transitive_dependents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            for evidence_id in ("scope", "routes", "model"):
                self.add_evidence(root, evidence_id)
            self.assertEqual(run(TRANSITION, tmp, "authorize", "complete", "--evidence", "scope").returncode, 0)
            self.assertEqual(run(TRANSITION, tmp, "discover", "in_progress").returncode, 0)
            self.assertEqual(run(TRANSITION, tmp, "discover", "complete", "--evidence", "routes").returncode, 0)
            self.assertEqual(run(TRANSITION, tmp, "model", "in_progress").returncode, 0)
            self.assertEqual(run(TRANSITION, tmp, "model", "complete", "--evidence", "model").returncode, 0)

            reopened = run(TRANSITION, tmp, "discover", "in_progress", "--reason", "new routes")
            self.assertEqual(reopened.returncode, 2)
            self.assertIn("dependent stage", reopened.stderr)

    def test_concurrent_transitions_preserve_both_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            self.add_evidence(root, "scope")
            self.assertEqual(run(TRANSITION, tmp, "authorize", "complete", "--evidence", "scope").returncode, 0)
            env = dict(os.environ, WEBSITE_MCP_TEST_DELAY_AFTER_READ="0.2")
            first = subprocess.Popen(
                [sys.executable, str(TRANSITION), tmp, "auth", "in_progress"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
            )
            second = subprocess.Popen(
                [sys.executable, str(TRANSITION), tmp, "discover", "in_progress"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
            )
            first_output = first.communicate(timeout=5)
            second_output = second.communicate(timeout=5)
            self.assertEqual(first.returncode, 0, first_output[1])
            self.assertEqual(second.returncode, 0, second_output[1])
            state = read_json(root / "state.json")
            statuses = {stage["id"]: stage["status"] for stage in state["stages"]}
            self.assertEqual(statuses["auth"], "in_progress")
            self.assertEqual(statuses["discover"], "in_progress")
            self.assertEqual([event["seq"] for event in state["history"]], list(range(1, len(state["history"]) + 1)))
            self.assertEqual(len(state["history"]), 4)

    def test_concurrent_checkpoint_and_iteration_writers_assign_unique_ordered_sequences(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, "http://127.0.0.1:9876")
            checkpoint_processes = [
                subprocess.Popen(
                    [
                        sys.executable,
                        str(APPROVE),
                        tmp,
                        "scope",
                        "--decision",
                        "approve",
                        "--artifact",
                        "spec.md",
                        "--actor",
                        f"local-uid:{os.getuid()}",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                for _ in range(18)
            ]
            for process in checkpoint_processes:
                _, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, stderr)
            checkpoints = [
                json.loads(line)
                for line in (root / "checkpoints.jsonl").read_text(encoding="utf-8").splitlines()
                if line
            ]
            self.assertEqual([record["seq"] for record in checkpoints], list(range(1, 19)))

        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, "http://127.0.0.1:9876")
            iteration_processes = [
                subprocess.Popen(
                    [sys.executable, str(DISCOVER), tmp, "http://127.0.0.1:9876"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                for _ in range(18)
            ]
            for process in iteration_processes:
                _, stderr = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 3, stderr)
            iterations = [
                json.loads(line)
                for line in (root / "discovery-iterations.jsonl").read_text(encoding="utf-8").splitlines()
                if line
            ]
            self.assertEqual([record["seq"] for record in iterations], list(range(1, 19)))

    def test_root_security_is_inherited_and_empty_operation_security_overrides_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            self.add_evidence(root, "scope")
            self.add_evidence(root, "routes")
            self.assertEqual(run(TRANSITION, tmp, "authorize", "complete", "--evidence", "scope").returncode, 0)
            self.assertEqual(run(TRANSITION, tmp, "auth", "in_progress").returncode, 0)
            self.assertEqual(run(TRANSITION, tmp, "discover", "in_progress").returncode, 0)
            self.assertEqual(run(TRANSITION, tmp, "discover", "complete", "--evidence", "routes").returncode, 0)
            openapi = read_json(root / "openapi.json")
            openapi["security"] = [{"oauth": []}]
            openapi["components"] = {
                "securitySchemes": {"oauth": {"type": "oauth2", "flows": {}}}
            }
            openapi["paths"] = {
                "/private": {"get": {"operationId": "private", "responses": {"200": {"description": "ok"}}, "x-mcp": {"route": "/private", "type": "read", "surface": "http"}}},
                "/public": {"get": {"operationId": "public", "security": [], "responses": {"200": {"description": "ok"}}, "x-mcp": {"route": "/public", "type": "read", "surface": "http"}}},
            }
            write_json(root / "openapi.json", openapi)
            inherited = self.validate(tmp)
            self.assertNotEqual(inherited.returncode, 0)
            self.assertIn("protected discovery", inherited.stderr)
            del openapi["paths"]["/private"]
            write_json(root / "openapi.json", openapi)
            overridden = self.validate(tmp)
            self.assertEqual(overridden.returncode, 0, overridden.stderr)

    def test_openapi_rejects_dangling_and_unsafe_refs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            openapi = read_json(root / "openapi.json")
            openapi["components"] = {"schemas": {"Item": {"type": "object"}}}
            openapi["paths"] = {"/items": {"get": {"operationId": "items", "responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Missing"}}}}}, "x-mcp": {"route": "/items", "type": "read", "surface": "http"}}}}
            write_json(root / "openapi.json", openapi)
            dangling = self.validate(tmp)
            self.assertNotEqual(dangling.returncode, 0)
            self.assertIn("dangling $ref", dangling.stderr)
            openapi["paths"]["/items"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"] = "../../secret.json"
            write_json(root / "openapi.json", openapi)
            unsafe = self.validate(tmp)
            self.assertNotEqual(unsafe.returncode, 0)
            self.assertIn("unsafe $ref", unsafe.stderr)

    def test_all_evidence_reference_locations_must_resolve(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            state = read_json(root / "state.json")
            state["history"][0]["evidence"] = ["missing-history"]
            event_payload = {key: value for key, value in state["history"][0].items() if key != "hash"}
            state["history"][0]["hash"] = hashlib.sha256(
                json.dumps(event_payload, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            write_json(root / "state.json", state)
            auth = read_json(root / "auth.json")
            auth["evidence"] = ["missing-auth"]
            write_json(root / "auth.json", auth)
            cli = read_json(root / "cli.json")
            cli["commands"] = [{"id": "x", "executable_ref": "x", "version_evidence": "missing-version", "arguments_schema": {}, "stdout_schema": {}, "exit_codes": {}, "side_effect": "read", "timeout_ms": 1, "evidence": []}]
            write_json(root / "cli.json", cli)
            openapi = read_json(root / "openapi.json")
            openapi["paths"] = {"/x": {"get": {"operationId": "x", "responses": {"200": {"description": "ok"}}, "x-mcp": {"route": "/x", "type": "read", "surface": "http", "evidence": ["missing-route"]}}}}
            write_json(root / "openapi.json", openapi)
            coverage = read_json(root / "coverage.json")
            coverage["gaps"] = [{"id": "g", "capability": "x", "impact": "x", "evidence": ["missing-gap"], "workaround": "none", "owner": "lead", "disposition": "open"}]
            write_json(root / "coverage.json", coverage)
            invalid = self.validate(tmp)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("missing-history", invalid.stderr)
            self.assertIn("missing-auth", invalid.stderr)
            self.assertIn("missing-version", invalid.stderr)
            self.assertIn("missing-route", invalid.stderr)
            self.assertIn("missing-gap", invalid.stderr)

    def test_har_jsonl_and_non_string_secret_references_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "capture.har").write_text(json.dumps({"log": {"entries": [{"request": {"headers": {"cookie": "session-value"}}}]}}), encoding="utf-8")
            (evidence / "events.jsonl").write_text(json.dumps({"nested": {"token": "small-secret"}}) + "\n", encoding="utf-8")
            auth = read_json(root / "auth.json")
            auth["modes"] = [{"id": "oauth", "kind": "oauth", "secret_ref": 123}]
            write_json(root / "auth.json", auth)
            invalid = self.validate(tmp)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("capture.har", invalid.stderr)
            self.assertIn("events.jsonl", invalid.stderr)
            self.assertIn("invalid secret reference", invalid.stderr)

    def test_validator_transition_force_and_repair_reject_unsafe_workspace_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp)
            outside = project / "outside"
            outside.mkdir()
            os.symlink(outside, project / ".website-mcp")
            self.assertNotEqual(self.validate(tmp).returncode, 0)
            self.assertNotEqual(run(TRANSITION, tmp, "authorize", "complete", "--evidence", "x").returncode, 0)

        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            outside = Path(tmp) / "outside.txt"
            outside.write_text("x", encoding="utf-8")
            os.symlink(outside, root / "unsafe-link")
            unsafe_validation = self.validate(tmp)
            self.assertNotEqual(unsafe_validation.returncode, 0)
            self.assertIn("symlink", unsafe_validation.stderr)
            forced = run(SCAFFOLD, tmp, "https://example.test", "--force")
            self.assertEqual(forced.returncode, 2)
            self.assertIn("symlink", forced.stderr)

        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            backup_target = Path(tmp) / "outside-backups"
            backup_target.mkdir()
            os.symlink(backup_target, Path(tmp) / ".website-mcp.backups")
            forced = run(SCAFFOLD, tmp, "https://example.test", "--force")
            self.assertEqual(forced.returncode, 2)
            self.assertIn("backup", forced.stderr)

            self.add_evidence(root, "scope")
            lock_target = Path(tmp) / "outside-lock"
            lock_target.write_text("", encoding="utf-8")
            os.symlink(lock_target, Path(tmp) / ".website-mcp.lock")
            transitioned = run(TRANSITION, tmp, "authorize", "complete", "--evidence", "scope")
            self.assertEqual(transitioned.returncode, 2)
            self.assertIn("lock", transitioned.stderr)

        for malformed in (None, "{broken"):
            with tempfile.TemporaryDirectory() as tmp:
                root = self.scaffold(tmp)
                if malformed is None:
                    (root / "state.json").unlink()
                else:
                    (root / "state.json").write_text(malformed, encoding="utf-8")
                repaired = run(SCAFFOLD, tmp, "https://example.test", "--repair")
                self.assertEqual(repaired.returncode, 2)
                self.assertIn("state.json", repaired.stderr)

        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            openapi = read_json(root / "openapi.json")
            openapi["servers"] = [{"url": "https://other.test"}]
            write_json(root / "openapi.json", openapi)
            repaired = run(SCAFFOLD, tmp, "https://example.test", "--repair")
            self.assertEqual(repaired.returncode, 2)
            self.assertIn("target", repaired.stderr)

    def test_build_graph_fields_structured_gaps_and_native_verified_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            self.add_evidence(root, "route")
            openapi = read_json(root / "openapi.json")
            openapi["paths"] = {"/items": {"get": {"operationId": "items", "responses": {"200": {"description": "ok"}}, "x-mcp": {"route": "/items", "type": "read", "surface": "http", "evidence": ["route"]}}}}
            write_json(root / "openapi.json", openapi)
            graph = read_json(root / "action-graph.json")
            graph["nodes"] = [{"id": "items", "operations": ["items"], "native": "yes", "evidence": ["route"], "confidence": "observed"}]
            write_json(root / "action-graph.json", graph)
            coverage = read_json(root / "coverage.json")
            coverage["route_counts"] = {"observed": 1, "modeled": 1, "verified": 0}
            coverage["action_counts"] = {"observed": 1, "native": 1, "verified": 0}
            coverage["gaps"] = [{}]
            write_json(root / "coverage.json", coverage)
            invalid = self.validate(tmp, "build")
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("missing required fields", invalid.stderr)
            self.assertIn("native=yes requires verified", invalid.stderr)
            self.assertIn("coverage.gaps[0] missing", invalid.stderr)

    def test_release_requires_distinct_fresh_stage_proof_classes_and_auth_disposition(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.make_release_workspace(tmp)
            valid = self.validate(tmp, "release")
            self.assertEqual(valid.returncode, 0, valid.stderr)

            auth = read_json(root / "auth.json")
            auth["status"] = "unknown"
            write_json(root / "auth.json", auth)
            bad_auth = self.validate(tmp, "release")
            self.assertNotEqual(bad_auth.returncode, 0)
            self.assertIn("auth.status", bad_auth.stderr)
            auth["status"] = "anonymous"
            write_json(root / "auth.json", auth)

            evidence = read_json(root / "evidence-index.json")
            benchmark = next(record for record in evidence["records"] if record["id"] == "benchmark")
            benchmark["fresh_until"] = "2000-01-01T00:00:00Z"
            write_json(root / "evidence-index.json", evidence)
            stale = self.validate(tmp, "release")
            self.assertNotEqual(stale.returncode, 0)
            self.assertIn("stale", stale.stderr)

            benchmark["fresh_until"] = "2099-01-01T00:00:00Z"
            benchmark["kind"] = "generic"
            benchmark["scope"] = "generic"
            write_json(root / "evidence-index.json", evidence)
            wrong_class = self.validate(tmp, "release")
            self.assertNotEqual(wrong_class.returncode, 0)
            self.assertIn("benchmark", wrong_class.stderr)

    def test_build_requires_typed_binding_and_reconciled_unique_gaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            self.add_evidence(root, "ui-proof")
            graph = read_json(root / "action-graph.json")
            graph["nodes"] = [
                {
                    "id": "profile.edit",
                    "intent": 7,
                    "surface": "ui",
                    "operations": [],
                    "commands": ["missing-cli"],
                    "native": "fallback",
                    "execution": "independent",
                    "auth": [],
                    "side_effect": "write",
                    "confirmation": "required",
                    "evidence": ["ui-proof"],
                    "confidence": "observed",
                }
            ]
            write_json(root / "action-graph.json", graph)
            coverage = read_json(root / "coverage.json")
            coverage["action_counts"] = {"observed": 1, "native": 0, "verified": 0}
            coverage["gaps"] = [
                {"id": "duplicate", "capability": "missing", "impact": "x", "evidence": ["ui-proof"], "workaround": "ui", "owner": "lead", "disposition": "bogus"},
                {"id": "duplicate", "capability": "missing", "impact": "x", "evidence": ["ui-proof"], "workaround": "ui", "owner": "lead", "disposition": "open"},
            ]
            write_json(root / "coverage.json", coverage)
            invalid = self.validate(tmp, "build")
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("intent must be", invalid.stderr)
            self.assertIn("unknown CLI command", invalid.stderr)
            self.assertIn("gap id is duplicated", invalid.stderr)
            self.assertIn("capability does not resolve", invalid.stderr)
            self.assertIn("disposition is invalid", invalid.stderr)

            coverage["gaps"] = []
            write_json(root / "coverage.json", coverage)
            unreconciled = self.validate(tmp, "build")
            self.assertNotEqual(unreconciled.returncode, 0)
            self.assertIn("unreconciled capability", unreconciled.stderr)

    def test_discover_completion_atomically_enforces_effective_security(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            self.add_evidence(root, "scope")
            self.add_evidence(root, "routes")
            self.assertEqual(run(TRANSITION, tmp, "authorize", "complete", "--evidence", "scope").returncode, 0)
            self.assertEqual(run(TRANSITION, tmp, "auth", "in_progress").returncode, 0)
            self.assertEqual(run(TRANSITION, tmp, "discover", "in_progress").returncode, 0)
            openapi = read_json(root / "openapi.json")
            openapi["security"] = [{"oauth": []}]
            openapi["paths"] = {"/private": {"get": {"operationId": "private", "responses": {"200": {"description": "ok"}}, "x-mcp": {"route": "/private", "type": "read", "surface": "http"}}}}
            write_json(root / "openapi.json", openapi)
            protected = run(TRANSITION, tmp, "discover", "complete", "--evidence", "routes")
            self.assertEqual(protected.returncode, 2)
            self.assertIn("protected", protected.stderr)
            openapi["paths"]["/private"]["get"]["security"] = []
            write_json(root / "openapi.json", openapi)
            public = run(TRANSITION, tmp, "discover", "complete", "--evidence", "routes")
            self.assertEqual(public.returncode, 0, public.stderr)

    def test_plain_and_yaml_sensitive_assignments_are_detected_conservatively(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "config.yaml").write_text("nested:\n  password: hunter2\n", encoding="utf-8")
            (evidence / "trace.txt").write_text("token = small-secret\n", encoding="utf-8")
            invalid = self.validate(tmp)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("config.yaml", invalid.stderr)
            self.assertIn("trace.txt", invalid.stderr)
            (evidence / "config.yaml").write_text("password: ${TARGET_PASSWORD}\n", encoding="utf-8")
            (evidence / "trace.txt").write_text("token = [REDACTED]\n", encoding="utf-8")
            safe = self.validate(tmp)
            self.assertEqual(safe.returncode, 0, safe.stderr)

    def test_malformed_container_types_report_findings_without_traceback(self):
        mutations = {
            "auth.json": ("modes", None),
            "action-graph.json": ("nodes", None),
            "cli.json": ("commands", None),
            "coverage.json": ("gaps", None),
        }
        for filename, (field, value) in mutations.items():
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as tmp:
                root = self.scaffold(tmp)
                document = read_json(root / filename)
                document[field] = value
                write_json(root / filename, document)
                for level in ("build", "release"):
                    invalid = self.validate(tmp, level)
                    self.assertNotEqual(invalid.returncode, 0)
                    self.assertNotIn("Traceback", invalid.stderr)
                    self.assertIn("must be", invalid.stderr)

    def test_repair_regenerates_missing_openapi_but_refuses_malformed_existing_openapi(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            (root / "openapi.json").unlink()
            repaired = run(SCAFFOLD, tmp, "https://example.test", "--repair")
            self.assertEqual(repaired.returncode, 0, repaired.stderr)
            self.assertEqual(read_json(root / "openapi.json")["servers"][0]["url"], "https://example.test")
            (root / "openapi.json").write_text("{broken", encoding="utf-8")
            malformed = run(SCAFFOLD, tmp, "https://example.test", "--repair")
            self.assertEqual(malformed.returncode, 2)
            self.assertIn("openapi.json is malformed", malformed.stderr)

    def test_nested_null_reference_lists_never_raise_tracebacks(self):
        mutations = {
            "auth.json": lambda document: document.update(
                {"modes": [{"id": "anonymous", "kind": "anonymous", "evidence": None}]}
            ),
            "action-graph.json": lambda document: document.update(
                {"nodes": [{"id": "x", "operations": None, "commands": None, "auth": None, "evidence": None}]}
            ),
            "cli.json": lambda document: document.update(
                {"commands": [{"id": "x", "executable_ref": "x", "version_evidence": None, "arguments_schema": {}, "stdout_schema": {}, "exit_codes": {}, "side_effect": "read", "timeout_ms": 1, "evidence": None}]}
            ),
            "openapi.json": lambda document: document.update(
                {"paths": {"/x": {"get": {"operationId": "x", "responses": {"200": {"description": "ok"}}, "x-mcp": {"route": "/x", "type": "read", "surface": "http", "evidence": None}}}}}
            ),
        }
        for filename, mutate in mutations.items():
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as tmp:
                root = self.scaffold(tmp)
                document = read_json(root / filename)
                mutate(document)
                write_json(root / filename, document)
                for level in ("build", "release"):
                    invalid = self.validate(tmp, level)
                    self.assertNotEqual(invalid.returncode, 0)
                    self.assertNotIn("Traceback", invalid.stderr)
                    self.assertIn("must be", invalid.stderr)

    def test_release_normalizes_malformed_evidence_records_and_state_stages(self):
        mutations = {
            "evidence-index.json": ("records", None),
            "state.json": ("stages", None),
            "state.json-list": ("stages", {"not": "a list"}),
        }
        for label, (field, value) in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                root = self.scaffold(tmp)
                filename = "state.json" if label.startswith("state.json") else label
                document = read_json(root / filename)
                document[field] = value
                write_json(root / filename, document)
                invalid = self.validate(tmp, "release")
                self.assertNotEqual(invalid.returncode, 0)
                self.assertNotIn("Traceback", invalid.stderr)
                self.assertIn("must be an array", invalid.stderr)

    def test_structured_gap_semantics_require_nonempty_fields_and_valid_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            self.add_evidence(root, "ui-proof")
            graph = read_json(root / "action-graph.json")
            graph["nodes"] = [
                {
                    "id": "ui.edit",
                    "intent": "Edit through UI",
                    "surface": "ui",
                    "operations": [],
                    "native": "fallback",
                    "execution": "independent",
                    "auth": [],
                    "side_effect": "write",
                    "confirmation": "required",
                    "evidence": ["ui-proof"],
                    "confidence": "observed",
                }
            ]
            write_json(root / "action-graph.json", graph)
            coverage = read_json(root / "coverage.json")
            coverage["action_counts"] = {"observed": 1, "native": 0, "verified": 0}
            coverage["gaps"] = [
                {
                    "id": "",
                    "capability": "ui.edit",
                    "impact": " ",
                    "evidence": [],
                    "workaround": "",
                    "owner": None,
                    "disposition": "open",
                }
            ]
            write_json(root / "coverage.json", coverage)
            invalid = self.validate(tmp, "build")
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("id must be a non-empty string", invalid.stderr)
            self.assertIn("impact must be a non-empty string", invalid.stderr)
            self.assertIn("workaround must be a non-empty string", invalid.stderr)
            self.assertIn("owner must be a non-empty string", invalid.stderr)
            self.assertIn("open disposition requires non-empty valid evidence", invalid.stderr)

    def test_scanner_uses_content_policy_for_arbitrary_suffix_malformed_json_and_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "capture.weird").write_text("password = visible-secret\n", encoding="utf-8")
            (evidence / "broken.har").write_text('{"log": ', encoding="utf-8")
            (evidence / "blob.bin").write_bytes(b"\x00\xff\x01")
            invalid = self.validate(tmp)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("capture.weird", invalid.stderr)
            self.assertIn("malformed JSON", invalid.stderr)
            self.assertIn("binary content requires explicit handling", invalid.stderr)

    def test_cli_contract_fields_are_safe_typed_and_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            self.add_evidence(root, "cli-proof")
            cli = read_json(root / "cli.json")
            cli["commands"] = [
                {
                    "id": "bad",
                    "executable_ref": "sh -c dangerous",
                    "version_evidence": "cli-proof",
                    "arguments_schema": None,
                    "stdout_schema": [],
                    "exit_codes": {"success": "", "999": 3},
                    "side_effect": "mystery",
                    "timeout_ms": -1,
                    "evidence": ["cli-proof"],
                }
            ]
            write_json(root / "cli.json", cli)
            invalid = self.validate(tmp, "build")
            self.assertNotEqual(invalid.returncode, 0)
            for finding in (
                "executable_ref is unsafe",
                "arguments_schema must be an object",
                "stdout_schema must be an object",
                "side_effect is invalid",
                "timeout_ms must be",
                "exit_codes must include success code 0",
                "exit code key is invalid",
            ):
                self.assertIn(finding, invalid.stderr)

    def test_dynamic_evidence_classes_require_future_fresh_until(self):
        for kind in ("auth-proof", "e2e", "benchmark", "cold-agent", "agent-evaluate", "hardening"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                root = self.scaffold(tmp)
                self.add_evidence(root, "dynamic", kind=kind, scope=kind)
                invalid = self.validate(tmp)
                self.assertNotEqual(invalid.returncode, 0)
                self.assertIn("cannot be immutable", invalid.stderr)
                self.assertIn("requires fresh_until", invalid.stderr)

    def test_transition_rejects_malformed_history_and_stages_without_mutation(self):
        mutations = [
            ("history", None),
            ("history", [None]),
            ("stages", None),
            ("stages", [None]),
        ]
        for field, value in mutations:
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as tmp:
                root = self.scaffold(tmp)
                state = read_json(root / "state.json")
                state[field] = value
                write_json(root / "state.json", state)
                before = tree_hashes(root)
                invalid = run(TRANSITION, tmp, "authorize", "complete", "--evidence", "missing")
                self.assertEqual(invalid.returncode, 2)
                self.assertNotIn("Traceback", invalid.stderr)
                self.assertEqual(tree_hashes(root), before)

        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            self.add_evidence(root, "scope")
            state = read_json(root / "state.json")
            state["stages"][0]["evidence"] = None
            write_json(root / "state.json", state)
            before = tree_hashes(root)
            invalid = run(TRANSITION, tmp, "authorize", "complete", "--evidence", "scope")
            self.assertEqual(invalid.returncode, 2)
            self.assertNotIn("Traceback", invalid.stderr)
            self.assertEqual(tree_hashes(root), before)

    def test_transition_module_imports_without_fcntl(self):
        script = (
            "import builtins,runpy,sys;"
            f"sys.path.insert(0,{str(TRANSITION.parent)!r});"
            "real=builtins.__import__;"
            "builtins.__import__=lambda name,*a,**k: "
            "(_ for _ in ()).throw(ImportError('blocked')) if name=='fcntl' else real(name,*a,**k);"
            f"runpy.run_path({str(TRANSITION)!r}, run_name='portable_import')"
        )
        result = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True, timeout=10
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_supported_openapi_subset_validates_version_paths_parameters_responses_and_security(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp)
            openapi = read_json(root / "openapi.json")
            openapi["openapi"] = "3.1"
            openapi["info"] = None
            openapi["security"] = [{"missingScheme": []}]
            openapi["paths"] = {
                "items/{id": {
                    "get": {
                        "operationId": "getItem",
                        "responses": {"banana": None},
                        "x-mcp": {"route": "items/{id", "type": "read", "surface": "http"},
                    }
                },
                "/items/{id}": {
                    "get": {
                        "operationId": "getItem2",
                        "responses": {"200": {"description": "ok"}},
                        "x-mcp": {"route": "/items/{id}", "type": "read", "surface": "http"},
                    }
                },
            }
            write_json(root / "openapi.json", openapi)
            invalid = self.validate(tmp)
            self.assertNotEqual(invalid.returncode, 0)
            for finding in (
                "exact 3.1.x",
                "openapi.info must be an object",
                "path template is invalid",
                "missing required path parameter declaration: id",
                "response key is invalid",
                "unknown security scheme",
            ):
                self.assertIn(finding, invalid.stderr)
            openapi.pop("paths")
            write_json(root / "openapi.json", openapi)
            missing_paths = self.validate(tmp)
            self.assertNotEqual(missing_paths.returncode, 0)
            self.assertIn("openapi.paths is required", missing_paths.stderr)


if __name__ == "__main__":
    unittest.main()
