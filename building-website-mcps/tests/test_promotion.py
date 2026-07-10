import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
if str(TESTS) not in sys.path:
    sys.path.insert(0, str(TESTS))

from fixture_harness import fixture_site, json_request, request

SCAFFOLD = ROOT / "scripts" / "scaffold_workspace.py"
PROMOTE = ROOT / "scripts" / "promote_capabilities.py"
RECORD_E2E = ROOT / "scripts" / "record_e2e_proof.py"
VALIDATE = ROOT / "scripts" / "validate_workspace.py"
GENERATE = ROOT / "scripts" / "generate_mcp.py"


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def command(*arguments: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *(str(argument) for argument in arguments)],
        text=True,
        capture_output=True,
        timeout=10,
    )


def promotion_record(
    workspace: Path,
    evidence_id: str,
    *,
    kind: str = "e2e",
    binding_capability: str = "products.list",
    fresh_until: str | None = None,
) -> None:
    artifact = workspace / "evidence" / f"{evidence_id}.json"
    artifact.parent.mkdir(exist_ok=True)
    artifact.write_text(
        json.dumps(
            {
                "fixture": "public_catalog",
                "capability": binding_capability,
                "operation": "products.list",
                "result": "real HTTP list returned a product",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    index = json.loads((workspace / "evidence-index.json").read_text(encoding="utf-8"))
    record: dict[str, object] = {
        "id": evidence_id,
        "kind": kind,
        "source": "real fixture HTTP request",
        "captured_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scope": "capability-promotion",
        "redactions": [],
        "redaction_verified": True,
        "artifact": str(artifact.relative_to(workspace)),
        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "promotion": {
            "bindings": [
                {
                    "capability_id": binding_capability,
                    "operations": ["products.list"],
                    "commands": [],
                }
            ]
        },
    }
    if kind in {"e2e", "contract"}:
        record["fresh_until"] = fresh_until or (
            datetime.now(timezone.utc) + timedelta(minutes=10)
        ).isoformat().replace("+00:00", "Z")
    else:
        record["immutable"] = True
    index["records"].append(record)
    write_json(workspace / "evidence-index.json", index)


def candidate_workspace(
    project: Path,
    *,
    evidence_kind: str = "e2e",
    target: str = "https://fixture.test",
) -> Path:
    scaffolded = command(SCAFFOLD, project, target)
    if scaffolded.returncode:
        raise AssertionError(scaffolded.stderr)
    workspace = project / ".website-mcp"
    promotion_record(workspace, "candidate-proof", kind=evidence_kind)
    write_json(
        workspace / "openapi.json",
        {
            "openapi": "3.1.0",
            "info": {"title": "Promotion fixture", "version": "1"},
            "servers": [{"url": target}],
            "paths": {
                "/api/products": {
                    "get": {
                        "operationId": "products.list",
                        "security": [],
                        "responses": {"200": {"description": "product list"}},
                        "x-mcp": {
                            "route": "/api/products",
                            "type": "read",
                            "surface": "http",
                            "evidence": ["candidate-proof"],
                        },
                    }
                }
            },
        },
    )
    write_json(
        workspace / "auth.json",
        {
            "version": 2,
            "status": "anonymous",
            "secret_policy": "references-only",
            "evidence": [],
            "modes": [{"id": "anonymous", "kind": "anonymous", "evidence": []}],
        },
    )
    write_json(workspace / "cli.json", {"version": 2, "commands": []})
    write_json(
        workspace / "action-graph.json",
        {
            "version": 2,
            "nodes": [
                {
                    "id": "products.list",
                    "intent": "List products",
                    "surface": "http",
                    "operations": ["products.list"],
                    "commands": [],
                    "native": "candidate",
                    "execution": "independent",
                    "auth": ["anonymous"],
                    "side_effect": "read",
                    "confirmation": "none",
                    "evidence": ["candidate-proof"],
                    "confidence": "inferred",
                }
            ],
            "edges": [],
        },
    )
    write_json(
        workspace / "coverage.json",
        {
            "version": 2,
            "route_counts": {"observed": 1, "modeled": 1, "verified": 0},
            "action_counts": {"observed": 1, "native": 0, "verified": 0},
            "gaps": [
                {
                    "id": "products-list-candidate",
                    "capability": "products.list",
                    "impact": "not executable until exact fixture proof is promoted",
                    "evidence": ["candidate-proof"],
                    "workaround": "use discovery tools only",
                    "owner": "fixture-test",
                    "disposition": "open",
                }
            ],
        },
    )
    return workspace


def replace_evidence_artifact(workspace: Path, evidence_id: str, proof: object) -> None:
    index_path = workspace / "evidence-index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    record = next(item for item in index["records"] if item["id"] == evidence_id)
    artifact = workspace / record["artifact"]
    artifact.write_text(json.dumps(proof, sort_keys=True) + "\n", encoding="utf-8")
    record["sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
    write_json(index_path, index)


class CapabilityPromotionTest(unittest.TestCase):
    def promote(self, project: Path, *extra: str) -> subprocess.CompletedProcess[str]:
        return command(PROMOTE, project, "products.list", "--evidence", "candidate-proof", *extra)

    def record(self, project: Path, evidence_id: str, argv: list[str], *extra: str) -> subprocess.CompletedProcess[str]:
        return command(
            RECORD_E2E,
            project,
            "products.list",
            "--evidence-id",
            evidence_id,
            "--operations-json",
            '["products.list"]',
            "--commands-json",
            "[]",
            "--argv-json",
            json.dumps(argv),
            *extra,
        )

    def test_recorder_runs_explicit_argv_and_promoter_can_use_redacted_e2e_record(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            workspace = candidate_workspace(project)
            proof = Path(temporary) / "real_e2e.py"
            proof.write_text('import json\nprint(json.dumps({"status": "passed"}))\n', encoding="utf-8")
            argv_file = Path(temporary) / "real-e2e.argv.json"
            argv_file.write_text(json.dumps([sys.executable, str(proof)]), encoding="utf-8")

            recorded = command(
                RECORD_E2E,
                project,
                "products.list",
                "--evidence-id",
                "recorded-e2e",
                "--operations-json",
                '["products.list"]',
                "--commands-json",
                "[]",
                "--argv-file",
                argv_file,
            )

            self.assertEqual(recorded.returncode, 0, recorded.stderr)
            index = json.loads((workspace / "evidence-index.json").read_text(encoding="utf-8"))
            record = next(item for item in index["records"] if item["id"] == "recorded-e2e")
            self.assertEqual(record["kind"], "e2e")
            self.assertIn("fresh_until", record)
            self.assertEqual(record["promotion"]["bindings"], [{"capability_id": "products.list", "operations": ["products.list"], "commands": []}])
            artifact = json.loads((workspace / record["artifact"]).read_text(encoding="utf-8"))
            self.assertEqual(artifact["exit_code"], 0)
            self.assertNotIn("passed", json.dumps(artifact))
            self.assertIn("sha256", artifact["stdout"])
            promoted = command(PROMOTE, project, "products.list", "--evidence", "recorded-e2e")
            self.assertEqual(promoted.returncode, 0, promoted.stderr)

    def test_recorder_rejects_unbound_shell_nonzero_timeout_and_secret_output_without_recording(self):
        cases = (
            ("unbound", [sys.executable, "-c", "print('safe')"], ("--operations-json", "[]"), "declared binding does not exactly match"),
            ("shell", ["sh", "-c", "echo safe"], (), "shell commands are not allowed"),
            ("nonzero", [sys.executable, "-c", "raise SystemExit(7)"], (), "exited with status 7"),
            ("timeout", [sys.executable, "-c", "import time; time.sleep(2)"], ("--timeout-seconds", "1"), "timed out"),
            ("secret", [sys.executable, "-c", "print('token=not-for-evidence')"], (), "secret-bearing output"),
        )
        for label, argv, extra, expected in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                project = Path(temporary) / "project"
                workspace = candidate_workspace(project)
                if label == "unbound":
                    result = command(
                        RECORD_E2E,
                        project,
                        "products.list",
                        "--evidence-id",
                        "rejected-e2e",
                        "--operations-json",
                        "[]",
                        "--commands-json",
                        "[]",
                        "--argv-json",
                        json.dumps(argv),
                    )
                else:
                    result = self.record(project, "rejected-e2e", argv, *extra)
                self.assertEqual(result.returncode, 2)
                self.assertIn(expected, result.stderr)
                index = json.loads((workspace / "evidence-index.json").read_text(encoding="utf-8"))
                self.assertNotIn("rejected-e2e", {item["id"] for item in index["records"]})
                self.assertFalse((workspace / "evidence" / "rejected-e2e.json").exists())

    def test_discovery_evidence_cannot_promote_a_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            workspace = candidate_workspace(project, evidence_kind="route-discovery")
            graph_before = (workspace / "action-graph.json").read_bytes()
            coverage_before = (workspace / "coverage.json").read_bytes()

            result = self.promote(project)

            self.assertEqual(result.returncode, 2)
            self.assertIn("promotion evidence kind must be e2e or contract", result.stderr)
            self.assertEqual((workspace / "action-graph.json").read_bytes(), graph_before)
            self.assertEqual((workspace / "coverage.json").read_bytes(), coverage_before)

    def test_fresh_exact_e2e_proof_promotes_candidate_and_reconciles_coverage(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            workspace = candidate_workspace(project)

            result = self.promote(project)

            self.assertEqual(result.returncode, 0, result.stderr)
            graph = json.loads((workspace / "action-graph.json").read_text(encoding="utf-8"))
            node = graph["nodes"][0]
            self.assertEqual(node["native"], "yes")
            self.assertEqual(node["confidence"], "verified")
            self.assertEqual(node["evidence"], ["candidate-proof"])
            coverage = json.loads((workspace / "coverage.json").read_text(encoding="utf-8"))
            self.assertEqual(coverage["route_counts"], {"observed": 1, "modeled": 1, "verified": 1})
            self.assertEqual(coverage["action_counts"], {"observed": 1, "native": 1, "verified": 1})
            self.assertEqual(coverage["gaps"], [])
            validated = command(VALIDATE, project, "--level", "build")
            self.assertEqual(validated.returncode, 0, validated.stderr)

    def test_stale_hash_invalid_and_irrelevant_proof_do_not_mutate_workspace(self):
        cases = (
            ("stale", "evidence record must be stale"),
            ("hash-invalid", "evidence artifact must no longer match its digest"),
            ("irrelevant", "evidence binding must name another capability"),
        )
        for case, _description in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                project = Path(temporary) / "project"
                workspace = candidate_workspace(project)
                evidence_index = json.loads((workspace / "evidence-index.json").read_text(encoding="utf-8"))
                record = evidence_index["records"][0]
                if case == "stale":
                    record["fresh_until"] = "2000-01-01T00:00:00Z"
                    write_json(workspace / "evidence-index.json", evidence_index)
                    expected = "stale"
                elif case == "hash-invalid":
                    artifact = workspace / record["artifact"]
                    artifact.write_text("changed after capture\n", encoding="utf-8")
                    expected = "does not match artifact"
                else:
                    record["promotion"]["bindings"][0]["capability_id"] = "products.manual"
                    write_json(workspace / "evidence-index.json", evidence_index)
                    expected = "irrelevant to exact capability binding"
                graph_before = (workspace / "action-graph.json").read_bytes()
                coverage_before = (workspace / "coverage.json").read_bytes()

                result = self.promote(project)

                self.assertEqual(result.returncode, 2)
                self.assertIn(expected, result.stderr)
                self.assertEqual((workspace / "action-graph.json").read_bytes(), graph_before)
                self.assertEqual((workspace / "coverage.json").read_bytes(), coverage_before)

    def test_live_fixture_matrix_proves_three_surfaces_before_generated_execution(self):
        session_environment = {
            "FIXTURE_ADMIN_USER": "fixture-admin",
            "FIXTURE_ADMIN_PASSWORD": "fixture-password",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                fixture_site("public_catalog") as public,
                fixture_site("session_admin", session_environment) as session,
                fixture_site("hybrid_cli") as hybrid,
            ):
                public_list = json_request(public, "/api/products?limit=1")
                public_manual = request(public, "/api/products/p-1/manual")
                self.assertEqual(public_list[0], 200)
                self.assertEqual(public_manual[0], 200)
                self.assertTrue(public_manual[2].startswith(b"%PDF-fixture"))

                login = json_request(
                    session,
                    "/session",
                    method="POST",
                    value={"username": "fixture-admin", "password": "fixture-password"},
                )
                self.assertEqual(login[0], 200)
                cookie = login[1]["Set-Cookie"].split(";", 1)[0]
                csrf = login[2]["csrf"]
                session_headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
                session_read = json_request(session, "/api/items", headers=session_headers)
                session_write = json_request(
                    session,
                    "/api/items",
                    method="POST",
                    value={"name": "Promotion fixture", "quantity": 1},
                    headers={**session_headers, "Idempotency-Key": "promotion-fixture"},
                )
                self.assertEqual(session_read[0], 200)
                self.assertEqual(session_write[0], 201)

                hybrid_events = json_request(hybrid, "/api/projects/p-1/events?limit=1")
                cli_root = root / "hybrid-cli-root"
                cli_root.mkdir()
                cli = ROOT / "fixtures" / "hybrid_cli" / "fixture_cli.py"
                cli_environment = {**os.environ, "FIXTURE_CLI_OUTPUT_ROOT": str(cli_root)}
                inspected = subprocess.run(
                    [sys.executable, str(cli), "project", "inspect", "--id", "p-1"],
                    text=True,
                    capture_output=True,
                    env=cli_environment,
                    timeout=5,
                )
                rendered = subprocess.run(
                    [sys.executable, str(cli), "report", "render", "--project", "p-1", "--output", "fixture-report.json"],
                    text=True,
                    capture_output=True,
                    env=cli_environment,
                    timeout=5,
                )
                verified = subprocess.run(
                    [sys.executable, str(cli), "report", "verify", "--path", str(cli_root / "fixture-report.json")],
                    text=True,
                    capture_output=True,
                    env=cli_environment,
                    timeout=5,
                )
                self.assertEqual(hybrid_events[0], 200)
                self.assertEqual(inspected.returncode, 0, inspected.stderr)
                self.assertEqual(rendered.returncode, 0, rendered.stderr)
                self.assertEqual(verified.returncode, 0, verified.stderr)

                project = root / "project"
                workspace = candidate_workspace(project, target=str(public))
                replace_evidence_artifact(
                    workspace,
                    "candidate-proof",
                    {
                        "public_catalog": {
                            "list_status": public_list[0],
                            "manual_status": public_manual[0],
                            "manual_is_pdf": public_manual[2].startswith(b"%PDF-fixture"),
                        },
                        "admin_fixture": {
                            "read_status": session_read[0],
                            "write_status": session_write[0],
                        },
                        "hybrid_cli": {
                            "events_status": hybrid_events[0],
                            "inspect_status": inspected.returncode,
                            "render_status": rendered.returncode,
                            "verify_status": verified.returncode,
                        },
                    },
                )
                promoted = self.promote(project)
                self.assertEqual(promoted.returncode, 0, promoted.stderr)

                generated = root / "generated"
                generated_result = command(GENERATE, project, generated)
                self.assertEqual(generated_result.returncode, 0, generated_result.stderr)
                server = subprocess.Popen(
                    [sys.executable, str(generated / "server.py")],
                    cwd=generated,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                try:
                    assert server.stdin is not None and server.stdout is not None
                    for identifier, method, params in (
                        (1, "initialize", {"protocolVersion": "2025-06-18"}),
                        (
                            2,
                            "tools/call",
                            {
                                "name": "execute_capability",
                                "arguments": {"capability_id": "products.list", "arguments": {}},
                            },
                        ),
                    ):
                        server.stdin.write(json.dumps({"jsonrpc": "2.0", "id": identifier, "method": method, "params": params}) + "\n")
                        server.stdin.flush()
                        response = json.loads(server.stdout.readline())
                    listed = json.loads(response["result"]["content"][0]["text"])
                    self.assertEqual(listed["items"][0]["id"], "p-1")
                finally:
                    if server.stdin:
                        server.stdin.close()
                    server.terminate()
                    server.wait(timeout=3)
                    for stream in (server.stdout, server.stderr):
                        if stream:
                            stream.close()


if __name__ == "__main__":
    unittest.main()
