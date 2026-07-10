import json
import os
import select
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from fixture_harness import FIXTURES, fixture_site


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
GENERATOR = SCRIPTS / "generate_mcp.py"
SCAFFOLD = SCRIPTS / "scaffold_workspace.py"
PROBE = SCRIPTS / "mcp_probe.py"
DISCOVER = SCRIPTS / "discover_target.py"
APPROVE = SCRIPTS / "approve_checkpoint.py"
RECORD_E2E = SCRIPTS / "record_e2e_proof.py"
PROMOTE = SCRIPTS / "promote_capabilities.py"
APPROVAL_KEY = "website-mcp-test-approval-key"


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def bind_promotion_evidence(workspace: Path, evidence_id: str, nodes: list[dict]) -> None:
    """Bind the fixture contract artifact to every generated test capability."""
    index_path = workspace / "evidence-index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    record = next(item for item in index["records"] if item.get("id") == evidence_id)
    record["kind"] = "contract"
    record.pop("immutable", None)
    record["fresh_until"] = "2099-01-01T00:00:00Z"
    record["promotion"] = {
        "bindings": [
            {
                "capability_id": node["id"],
                "operations": node["operations"],
                "commands": node["commands"],
            }
            for node in nodes
        ]
    }
    write_json(index_path, index)


def public_catalog_workspace(project: Path, base: str) -> None:
    scaffold = subprocess.run(
        [sys.executable, str(SCAFFOLD), str(project), base],
        text=True,
        capture_output=True,
        timeout=5,
    )
    if scaffold.returncode:
        raise AssertionError(scaffold.stderr)
    workspace = project / ".website-mcp"
    evidence = workspace / "evidence" / "catalog-contract.json"
    evidence.parent.mkdir()
    evidence.write_text('{"source":"fixture"}\n', encoding="utf-8")
    import hashlib

    evidence_id = "catalog-contract"
    digest = hashlib.sha256(evidence.read_bytes()).hexdigest()
    write_json(
        workspace / "evidence-index.json",
        {
            "version": 2,
            "records": [
                {
                    "id": evidence_id,
                    "kind": "source-code",
                    "source": "fixture",
                    "captured_at": "2026-07-10T00:00:00Z",
                    "immutable": True,
                    "scope": "test",
                    "redactions": [],
                    "redaction_verified": True,
                    "artifact": "evidence/catalog-contract.json",
                    "sha256": digest,
                }
            ],
        },
    )
    response = {"200": {"description": "fixture response"}}
    operation = lambda route, kind, operation_id, parameters=[]: {
        "operationId": operation_id,
        "security": [],
        "parameters": parameters,
        "responses": response,
        "x-mcp": {"route": route, "type": kind, "surface": "http", "evidence": [evidence_id]},
    }
    identifier = {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
    product_query = [
        {"name": "q", "in": "query", "schema": {"type": "string"}},
        {"name": "fields", "in": "query", "schema": {"type": "string"}},
        {"name": "cursor", "in": "query", "schema": {"type": "string"}},
        {"name": "limit", "in": "query", "schema": {"type": "integer", "maximum": 50}},
    ]
    write_json(
        workspace / "openapi.json",
        {
            "openapi": "3.1.0",
            "info": {"title": "Public catalog", "version": "1"},
            "servers": [{"url": base}],
            "paths": {
                "/api/products": {"get": operation("/api/products", "read", "products.list", product_query)},
                "/api/products/{id}/manual": {
                    "get": operation("/api/products/{id}/manual", "download", "products.manual", [identifier])
                },
            },
        },
    )
    nodes = [
        {
            "id": "products.list",
            "intent": "List products",
            "surface": "http",
            "operations": ["products.list"],
            "commands": [],
            "native": "yes",
            "execution": "paginated",
            "auth": ["anonymous"],
            "side_effect": "read",
            "confirmation": "none",
            "evidence": [evidence_id],
            "confidence": "verified",
        },
        {
            "id": "products.manual",
            "intent": "Download product manual",
            "surface": "http",
            "operations": ["products.manual"],
            "commands": [],
            "native": "yes",
            "execution": "download-stream",
            "auth": ["anonymous"],
            "side_effect": "read",
            "confirmation": "none",
            "evidence": [evidence_id],
            "confidence": "verified",
        },
    ]
    write_json(workspace / "action-graph.json", {"version": 2, "nodes": nodes, "edges": []})
    bind_promotion_evidence(workspace, evidence_id, nodes)
    write_json(
        workspace / "auth.json",
        {"version": 2, "status": "anonymous", "secret_policy": "references-only", "evidence": [], "modes": [{"id": "anonymous", "kind": "anonymous", "evidence": []}]},
    )
    write_json(workspace / "cli.json", {"version": 2, "commands": []})
    write_json(
        workspace / "coverage.json",
        {
            "version": 2,
            "route_counts": {"observed": 2, "modeled": 2, "verified": 2},
            "action_counts": {"observed": 2, "native": 2, "verified": 2},
            "gaps": [],
        },
    )


class GeneratedMcpTest(unittest.TestCase):
    def start_server(self, generated: Path, *, env: dict[str, str] | None = None) -> subprocess.Popen[str]:
        return subprocess.Popen(
            [sys.executable, str(generated / "server.py")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=generated,
            env=env,
        )

    def rpc(self, server: subprocess.Popen[str], identifier: int, method: str, params: dict) -> dict:
        assert server.stdin is not None
        assert server.stdout is not None
        server.stdin.write(json.dumps({"jsonrpc": "2.0", "id": identifier, "method": method, "params": params}) + "\n")
        server.stdin.flush()
        return json.loads(server.stdout.readline())

    def stop_server(self, server: subprocess.Popen[str]) -> None:
        if server.stdin:
            server.stdin.close()
        server.terminate()
        server.wait(timeout=3)
        for stream in (server.stdout, server.stderr):
            if stream:
                stream.close()

    def test_generation_creates_self_contained_server_that_initializes(self):
        with tempfile.TemporaryDirectory() as tmp, fixture_site("public_catalog") as base:
            project = Path(tmp) / "project"
            generated = Path(tmp) / "generated"
            public_catalog_workspace(project, str(base))
            result = subprocess.run(
                [
                    sys.executable,
                    str(GENERATOR),
                    str(project),
                    str(generated),
                ],
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((generated / "server.py").is_file())
            self.assertTrue((generated / "runtime-config.json").is_file())
            self.assertTrue((generated / "mcp.json").is_file())
            self.assertTrue((generated / "skill" / "SKILL.md").is_file())

            server = self.start_server(generated)
            try:
                response = self.rpc(server, 1, "initialize", {"protocolVersion": "2025-06-18"})
                self.assertEqual(response["id"], 1)
                self.assertEqual(response["result"]["protocolVersion"], "2025-06-18")
            finally:
                self.stop_server(server)

    def test_cli_only_contract_promotes_generates_and_executes_over_stdio(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            generated = Path(tmp) / "generated"
            contract = json.loads((FIXTURES / "hybrid_cli" / "cli-contract.json").read_text())
            contract["execution"]["executable_ref"] = "env:FIXTURE_CLI_EXECUTABLE"
            contract_path = Path(tmp) / "cli-contract.json"
            write_json(contract_path, contract)
            env = {**os.environ, "WEBSITE_MCP_APPROVAL_KEY": APPROVAL_KEY}

            scaffold = subprocess.run(
                [sys.executable, str(SCAFFOLD), str(project), "cli://local"],
                text=True,
                capture_output=True,
                timeout=10,
                env=env,
            )
            self.assertEqual(scaffold.returncode, 0, scaffold.stderr)
            scope = subprocess.run(
                [
                    sys.executable,
                    str(APPROVE),
                    str(project),
                    "scope",
                    "--decision",
                    "approve",
                    "--artifact",
                    "spec.md",
                    "--actor",
                    f"local-uid:{os.getuid()}",
                ],
                text=True,
                capture_output=True,
                timeout=10,
                env=env,
            )
            self.assertEqual(scope.returncode, 0, scope.stderr)
            discovery = subprocess.run(
                [sys.executable, str(DISCOVER), str(project), "cli://local", "--cli-contract", str(contract_path)],
                text=True,
                capture_output=True,
                timeout=10,
                env=env,
            )
            self.assertEqual(discovery.returncode, 3, discovery.stderr)

            fixture_cli = FIXTURES / "hybrid_cli" / "fixture_cli.py"
            proof = subprocess.run(
                [
                    sys.executable,
                    str(RECORD_E2E),
                    str(project),
                    "project.inspect",
                    "--evidence-id",
                    "cli-inspect-e2e",
                    "--operations-json",
                    "[]",
                    "--commands-json",
                    '["project.inspect"]',
                    "--argv-json",
                    json.dumps([sys.executable, str(fixture_cli), "project", "inspect", "--id", "p-1"]),
                ],
                text=True,
                capture_output=True,
                timeout=10,
                env=env,
            )
            self.assertEqual(proof.returncode, 0, proof.stderr)
            promoted = subprocess.run(
                [sys.executable, str(PROMOTE), str(project), "project.inspect", "--evidence", "cli-inspect-e2e"],
                text=True,
                capture_output=True,
                timeout=10,
                env=env,
            )
            self.assertEqual(promoted.returncode, 0, promoted.stderr)

            generated_result = subprocess.run(
                [sys.executable, str(GENERATOR), str(project), str(generated)],
                text=True,
                capture_output=True,
                timeout=10,
                env=env,
            )
            self.assertEqual(generated_result.returncode, 0, generated_result.stderr)
            config = json.loads((generated / "runtime-config.json").read_text())
            self.assertEqual(config["base_url"], "cli://local")
            self.assertEqual(config["operations"], {})

            server = self.start_server(
                generated,
                env={
                    **env,
                    "WEBSITE_MCP_CLI_ROOT": str(fixture_cli.parent),
                    "FIXTURE_CLI_EXECUTABLE": str(fixture_cli),
                },
            )
            try:
                self.rpc(server, 1, "initialize", {"protocolVersion": "2025-06-18"})
                response = self.rpc(
                    server,
                    2,
                    "tools/call",
                    {
                        "name": "execute_capability",
                        "arguments": {"capability_id": "project.inspect", "arguments": {"id": "p-1"}},
                    },
                )
                self.assertEqual(json.loads(response["result"]["content"][0]["text"])["name"], "Project One")
            finally:
                self.stop_server(server)

    def test_clean_copy_needs_no_builder_import_and_probe_exercises_it(self):
        with tempfile.TemporaryDirectory() as tmp, fixture_site("public_catalog") as base:
            project = Path(tmp) / "project"
            generated = Path(tmp) / "generated"
            isolated = Path(tmp) / "isolated"
            public_catalog_workspace(project, str(base))
            result = subprocess.run(
                [sys.executable, str(GENERATOR), str(project), str(generated)],
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            shutil.copytree(generated, isolated)
            probe = subprocess.run(
                [sys.executable, str(PROBE), str(isolated)],
                text=True,
                capture_output=True,
                timeout=10,
                env={**os.environ, "PYTHONPATH": ""},
            )
            self.assertEqual(probe.returncode, 0, probe.stderr)
            self.assertEqual(json.loads(probe.stdout)["status"], "ok")
            self.assertNotIn(str(ROOT), (isolated / "server.py").read_text(encoding="utf-8"))

    def test_protocol_handles_notifications_errors_and_eof_without_stdout_logs(self):
        with tempfile.TemporaryDirectory() as tmp, fixture_site("public_catalog") as base:
            project = Path(tmp) / "project"
            generated = Path(tmp) / "generated"
            public_catalog_workspace(project, str(base))
            result = subprocess.run(
                [sys.executable, str(GENERATOR), str(project), str(generated)],
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            server = self.start_server(generated)
            try:
                assert server.stdin is not None
                assert server.stdout is not None
                server.stdin.write("{not json}\n")
                server.stdin.flush()
                parse_error = json.loads(server.stdout.readline())
                self.assertEqual(parse_error["error"]["code"], -32700)

                self.rpc(server, 1, "initialize", {"protocolVersion": "2025-06-18"})
                server.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}) + "\n")
                server.stdin.flush()
                self.assertEqual(select.select([server.stdout], [], [], 0.1)[0], [])

                tools = self.rpc(server, 2, "tools/list", {})
                self.assertEqual(
                    {item["name"] for item in tools["result"]["tools"]},
                    {"search_capabilities", "describe_capabilities", "plan_workflow", "execute_capability"},
                )
                missing = self.rpc(server, 3, "not/a/method", {})
                self.assertEqual(missing["error"]["code"], -32601)
            finally:
                self.stop_server(server)

    def test_promoted_http_read_preserves_query_and_downloads_to_path(self):
        with tempfile.TemporaryDirectory() as tmp, fixture_site("public_catalog") as base:
            project = Path(tmp) / "project"
            generated = Path(tmp) / "generated"
            public_catalog_workspace(project, str(base))
            generated_result = subprocess.run(
                [sys.executable, str(GENERATOR), str(project), str(generated)],
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(generated_result.returncode, 0, generated_result.stderr)
            download_root = Path(tmp) / "downloads"
            download_root.mkdir()
            manual = download_root / "p-1-manual.pdf"
            server = self.start_server(
                generated, env={**os.environ, "WEBSITE_MCP_DOWNLOAD_ROOT": str(download_root)}
            )
            try:
                self.rpc(server, 1, "initialize", {"protocolVersion": "2025-06-18"})
                listed = self.rpc(
                    server,
                    2,
                    "tools/call",
                    {
                        "name": "execute_capability",
                        "arguments": {
                            "capability_id": "products.list",
                            "arguments": {"q": "red", "fields": "id,name,price", "limit": 1},
                        },
                    },
                )
                listed_value = json.loads(listed["result"]["content"][0]["text"])
                self.assertEqual(listed_value["items"][0], {"id": "p-1", "name": "Red Mug", "price": 12.5})
                self.assertTrue(listed_value["next_cursor"])

                downloaded = self.rpc(
                    server,
                    3,
                    "tools/call",
                    {
                        "name": "execute_capability",
                        "arguments": {
                            "capability_id": "products.manual",
                            "arguments": {"id": "p-1", "download_path": "p-1-manual.pdf"},
                        },
                    },
                )
                file_value = json.loads(downloaded["result"]["content"][0]["text"])
                self.assertEqual(Path(file_value["path"]).resolve(), manual.resolve())
                self.assertEqual(file_value["size"], manual.stat().st_size)
                self.assertEqual(len(file_value["sha256"]), 64)
                self.assertTrue(manual.read_bytes().startswith(b"%PDF-fixture"))
            finally:
                self.stop_server(server)

    def test_hybrid_cli_uses_argv_allowlist_and_refuses_injection(self):
        with tempfile.TemporaryDirectory() as tmp, fixture_site("public_catalog") as base:
            project = Path(tmp) / "project"
            generated = Path(tmp) / "generated"
            public_catalog_workspace(project, str(base))
            workspace = project / ".website-mcp"
            cli_command = {
                "id": "project.inspect",
                "executable_ref": "env:FIXTURE_CLI_EXECUTABLE",
                "argv": ["project", "inspect", "--id={id}"],
                "version_evidence": "catalog-contract",
                "arguments_schema": {
                    "type": "object",
                    "required": ["id"],
                    "properties": {"id": {"type": "string", "pattern": "^p-[0-9]+$"}},
                    "additionalProperties": False,
                },
                "stdout_schema": {"type": "object"},
                "exit_codes": {"0": "success", "2": "invalid arguments"},
                "side_effect": "read",
                "timeout_ms": 3000,
                "evidence": ["catalog-contract"],
            }
            write_json(workspace / "cli.json", {"version": 2, "commands": [cli_command]})
            graph = json.loads((workspace / "action-graph.json").read_text(encoding="utf-8"))
            graph["nodes"].append(
                {
                    "id": "project.inspect",
                    "intent": "Inspect project",
                    "surface": "stdio",
                    "operations": [],
                    "commands": ["project.inspect"],
                    "native": "yes",
                    "execution": "independent",
                    "auth": [],
                    "side_effect": "read",
                    "confirmation": "none",
                    "evidence": ["catalog-contract"],
                    "confidence": "verified",
                }
            )
            write_json(workspace / "action-graph.json", graph)
            bind_promotion_evidence(workspace, "catalog-contract", graph["nodes"])
            coverage = json.loads((workspace / "coverage.json").read_text(encoding="utf-8"))
            coverage["action_counts"] = {"observed": 3, "native": 3, "verified": 3}
            write_json(workspace / "coverage.json", coverage)
            result = subprocess.run(
                [sys.executable, str(GENERATOR), str(project), str(generated)],
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            output_root = Path(tmp) / "cli-output"
            output_root.mkdir()
            environment = {
                **os.environ,
                "FIXTURE_CLI_EXECUTABLE": str(ROOT / "fixtures" / "hybrid_cli" / "fixture_cli.py"),
                "FIXTURE_CLI_OUTPUT_ROOT": str(output_root),
                "WEBSITE_MCP_CLI_ROOT": str(ROOT / "fixtures" / "hybrid_cli"),
            }
            server = self.start_server(generated, env=environment)
            try:
                self.rpc(server, 1, "initialize", {"protocolVersion": "2025-06-18"})
                inspected = self.rpc(
                    server,
                    2,
                    "tools/call",
                    {"name": "execute_capability", "arguments": {"capability_id": "project.inspect", "arguments": {"id": "p-1"}}},
                )
                self.assertEqual(json.loads(inspected["result"]["content"][0]["text"])["id"], "p-1")
                injection = self.rpc(
                    server,
                    3,
                    "tools/call",
                    {
                        "name": "execute_capability",
                        "arguments": {"capability_id": "project.inspect", "arguments": {"id": "p-1; echo injected"}},
                    },
                )
                self.assertEqual(injection["error"]["code"], -32602)
                self.assertEqual(injection["error"]["message"], "cli_argument_pattern_mismatch")
                self.assertFalse((output_root / "injected").exists())
            finally:
                self.stop_server(server)

    def test_cookie_session_read_reauthenticates_once_with_csrf_reference(self):
        fixture_env = {"FIXTURE_ADMIN_USER": "fixture-admin", "FIXTURE_ADMIN_PASSWORD": "fixture-password"}
        with tempfile.TemporaryDirectory() as tmp, fixture_site("session_admin", fixture_env) as base:
            project = Path(tmp) / "project"
            generated = Path(tmp) / "generated"
            public_catalog_workspace(project, str(base))
            workspace = project / ".website-mcp"
            evidence_id = "catalog-contract"
            write_json(
                workspace / "openapi.json",
                {
                    "openapi": "3.1.0",
                    "info": {"title": "Session admin", "version": "1"},
                    "servers": [{"url": str(base)}],
                    "paths": {
                        "/api/items": {
                            "get": {
                                "operationId": "items.list",
                                "security": [],
                                "parameters": [
                                    {"name": "cursor", "in": "query", "schema": {"type": "string"}},
                                    {"name": "limit", "in": "query", "schema": {"type": "integer", "maximum": 50}},
                                ],
                                "responses": {"200": {"description": "items"}},
                                "x-mcp": {"route": "/api/items", "type": "read", "surface": "http", "evidence": [evidence_id]},
                            }
                        }
                    },
                },
            )
            write_json(
                workspace / "auth.json",
                {
                    "version": 2,
                    "status": "verified",
                    "secret_policy": "references-only",
                    "evidence": [],
                    "modes": [
                        {
                            "id": "fixture-session",
                            "kind": "cookie-session",
                            "secret_ref": "env:FIXTURE_SESSION_COOKIE",
                            "header_name": "Cookie",
                            "csrf_ref": "env:FIXTURE_CSRF",
                            "csrf_header": "X-CSRF-Token",
                            "reauth": {
                                "path": "/session",
                                "method": "POST",
                                "body_env_ref": "env:FIXTURE_REAUTH_BODY",
                                "csrf_response_field": "csrf",
                            },
                            "evidence": [],
                        }
                    ],
                },
            )
            session_node = {
                "id": "items.list",
                "intent": "List admin items",
                "surface": "http",
                "operations": ["items.list"],
                "commands": [],
                "native": "yes",
                "execution": "paginated",
                "auth": ["fixture-session"],
                "side_effect": "read",
                "confirmation": "none",
                "evidence": [evidence_id],
                "confidence": "verified",
            }
            write_json(workspace / "action-graph.json", {"version": 2, "nodes": [session_node], "edges": []})
            bind_promotion_evidence(workspace, evidence_id, [session_node])
            write_json(
                workspace / "coverage.json",
                {"version": 2, "route_counts": {"observed": 1, "modeled": 1, "verified": 1}, "action_counts": {"observed": 1, "native": 1, "verified": 1}, "gaps": []},
            )
            result = subprocess.run(
                [sys.executable, str(GENERATOR), str(project), str(generated)],
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            server = self.start_server(
                generated,
                env={
                    **os.environ,
                    "FIXTURE_SESSION_COOKIE": "fixture_session=expired",
                    "FIXTURE_CSRF": "csrf-expired",
                    "FIXTURE_REAUTH_BODY": json.dumps({"username": "fixture-admin", "password": "fixture-password"}),
                },
            )
            try:
                self.rpc(server, 1, "initialize", {"protocolVersion": "2025-06-18"})
                listed = self.rpc(
                    server,
                    2,
                    "tools/call",
                    {"name": "execute_capability", "arguments": {"capability_id": "items.list", "arguments": {"limit": 1}}},
                )
                value = json.loads(listed["result"]["content"][0]["text"])
                self.assertEqual(value["items"][0]["id"], "i-1")
            finally:
                self.stop_server(server)

    def test_header_auth_uses_declared_header_injection_reference(self):
        with tempfile.TemporaryDirectory() as tmp, fixture_site("public_catalog") as base:
            project = Path(tmp) / "project"
            generated = Path(tmp) / "generated"
            public_catalog_workspace(project, str(base))
            workspace = project / ".website-mcp"
            write_json(
                workspace / "auth.json",
                {
                    "version": 2,
                    "status": "verified",
                    "secret_policy": "references-only",
                    "evidence": [],
                    "modes": [
                        {
                            "id": "fixture-header",
                            "kind": "api-key",
                            "secret_ref": "env:FIXTURE_HEADER_KEY",
                            "injection": "X-Fixture-Key header",
                            "evidence": [],
                        }
                    ],
                },
            )
            graph = json.loads((workspace / "action-graph.json").read_text(encoding="utf-8"))
            for node in graph["nodes"]:
                node["auth"] = ["fixture-header"]
            write_json(workspace / "action-graph.json", graph)
            bind_promotion_evidence(workspace, "catalog-contract", graph["nodes"])
            result = subprocess.run(
                [sys.executable, str(GENERATOR), str(project), str(generated)],
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            server = self.start_server(generated, env={**os.environ, "FIXTURE_HEADER_KEY": "header-value"})
            try:
                self.rpc(server, 1, "initialize", {"protocolVersion": "2025-06-18"})
                listed = self.rpc(
                    server,
                    2,
                    "tools/call",
                    {"name": "execute_capability", "arguments": {"capability_id": "products.list", "arguments": {}}},
                )
                self.assertIn("result", listed)
            finally:
                self.stop_server(server)

    def test_generator_rejects_openapi_server_outside_state_target_origin(self):
        with tempfile.TemporaryDirectory() as tmp, fixture_site("public_catalog") as base:
            project = Path(tmp) / "project"
            generated = Path(tmp) / "generated"
            public_catalog_workspace(project, str(base))
            workspace = project / ".website-mcp"
            openapi = json.loads((workspace / "openapi.json").read_text(encoding="utf-8"))
            openapi["servers"] = [{"url": "https://untrusted.example"}]
            write_json(workspace / "openapi.json", openapi)
            result = subprocess.run(
                [sys.executable, str(GENERATOR), str(project), str(generated)],
                text=True,
                capture_output=True,
                timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("origin", result.stderr)

    def test_mcp_manifest_launches_server_by_absolute_path(self):
        with tempfile.TemporaryDirectory() as tmp, fixture_site("public_catalog") as base:
            project = Path(tmp) / "project"
            generated = Path(tmp) / "generated"
            public_catalog_workspace(project, str(base))
            result = subprocess.run(
                [sys.executable, str(GENERATOR), str(project), str(generated)], text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads((generated / "mcp.json").read_text(encoding="utf-8"))
            self.assertEqual(Path(manifest["mcpServers"]["website-mcp"]["args"][0]), (generated / "server.py").resolve())

    def test_non_read_capability_requires_explicit_boolean_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp, fixture_site("public_catalog") as base:
            project = Path(tmp) / "project"
            generated = Path(tmp) / "generated"
            public_catalog_workspace(project, str(base))
            workspace = project / ".website-mcp"
            graph = json.loads((workspace / "action-graph.json").read_text(encoding="utf-8"))
            graph["nodes"][0]["side_effect"] = "write"
            graph["nodes"][0]["confirmation"] = "explicit boolean confirmation required"
            write_json(workspace / "action-graph.json", graph)
            bind_promotion_evidence(workspace, "catalog-contract", graph["nodes"])
            result = subprocess.run([sys.executable, str(GENERATOR), str(project), str(generated)], text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            server = self.start_server(generated)
            try:
                self.rpc(server, 1, "initialize", {"protocolVersion": "2025-06-18"})
                blocked = self.rpc(server, 2, "tools/call", {"name": "execute_capability", "arguments": {"capability_id": "products.list", "arguments": {}}})
                self.assertEqual(blocked["error"]["message"], "confirmation_required")
                allowed = self.rpc(server, 3, "tools/call", {"name": "execute_capability", "arguments": {"capability_id": "products.list", "confirmation": True, "arguments": {}}})
                self.assertIn("result", allowed)
            finally:
                self.stop_server(server)

    def test_http_refuses_body_or_file_io_not_declared_by_operation(self):
        with tempfile.TemporaryDirectory() as tmp, fixture_site("public_catalog") as base:
            project, generated = Path(tmp) / "project", Path(tmp) / "generated"
            public_catalog_workspace(project, str(base))
            result = subprocess.run([sys.executable, str(GENERATOR), str(project), str(generated)], text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            server = self.start_server(generated)
            try:
                self.rpc(server, 1, "initialize", {"protocolVersion": "2025-06-18"})
                body = self.rpc(server, 2, "tools/call", {"name": "execute_capability", "arguments": {"capability_id": "products.list", "arguments": {"body": {"ignored": True}}}})
                self.assertEqual(body["error"]["message"], "request_body_not_permitted")
                file_read = self.rpc(server, 3, "tools/call", {"name": "execute_capability", "arguments": {"capability_id": "products.list", "arguments": {"upload_path": "untrusted.txt"}}})
                self.assertEqual(file_read["error"]["message"], "upload_not_permitted")
            finally:
                self.stop_server(server)

    def test_declared_json_body_requires_minimum_schema_fields(self):
        with tempfile.TemporaryDirectory() as tmp, fixture_site("public_catalog") as base:
            project, generated = Path(tmp) / "project", Path(tmp) / "generated"
            public_catalog_workspace(project, str(base))
            workspace = project / ".website-mcp"
            openapi = json.loads((workspace / "openapi.json").read_text(encoding="utf-8"))
            operation = openapi["paths"]["/api/products"]["get"]
            operation["requestBody"] = {"content": {"application/json": {"schema": {"type": "object", "required": ["name"], "properties": {"name": {"type": "string"}}, "additionalProperties": False}}}}
            write_json(workspace / "openapi.json", openapi)
            result = subprocess.run([sys.executable, str(GENERATOR), str(project), str(generated)], text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            server = self.start_server(generated)
            try:
                self.rpc(server, 1, "initialize", {"protocolVersion": "2025-06-18"})
                missing = self.rpc(server, 2, "tools/call", {"name": "execute_capability", "arguments": {"capability_id": "products.list", "arguments": {"body": {}}}})
                self.assertEqual(missing["error"]["message"], "body_missing_required_name")
            finally:
                self.stop_server(server)

    def test_body_refuses_contract_without_application_json(self):
        with tempfile.TemporaryDirectory() as tmp, fixture_site("public_catalog") as base:
            project, generated = Path(tmp) / "project", Path(tmp) / "generated"
            public_catalog_workspace(project, str(base))
            workspace = project / ".website-mcp"
            openapi = json.loads((workspace / "openapi.json").read_text(encoding="utf-8"))
            openapi["paths"]["/api/products"]["get"]["requestBody"] = {"content": {"text/csv": {"schema": {"type": "string"}}}}
            write_json(workspace / "openapi.json", openapi)
            result = subprocess.run([sys.executable, str(GENERATOR), str(project), str(generated)], text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            server = self.start_server(generated)
            try:
                self.rpc(server, 1, "initialize", {"protocolVersion": "2025-06-18"})
                response = self.rpc(server, 2, "tools/call", {"name": "execute_capability", "arguments": {"capability_id": "products.list", "arguments": {"body": {}}}})
                self.assertEqual(response["error"]["message"], "request_body_json_not_declared")
            finally:
                self.stop_server(server)

    def test_upstream_error_secret_is_not_reflected_to_mcp(self):
        secret = "raw-bearer-secret-value"

        class Unauthorized(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_GET(self) -> None:
                body = json.dumps({"error": f"Bearer {secret}"}).encode()
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"session={secret}")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        listener = ThreadingHTTPServer(("127.0.0.1", 0), Unauthorized)
        thread = threading.Thread(target=listener.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                project, generated = Path(tmp) / "project", Path(tmp) / "generated"
                public_catalog_workspace(project, f"http://127.0.0.1:{listener.server_port}")
                result = subprocess.run([sys.executable, str(GENERATOR), str(project), str(generated)], text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                server = self.start_server(generated)
                try:
                    self.rpc(server, 1, "initialize", {"protocolVersion": "2025-06-18"})
                    response = self.rpc(server, 2, "tools/call", {"name": "execute_capability", "arguments": {"capability_id": "products.list", "arguments": {}}})
                    self.assertNotIn(secret, json.dumps(response))
                finally:
                    self.stop_server(server)
        finally:
            listener.shutdown()
            thread.join(timeout=3)
            listener.server_close()

    def test_reauthentication_never_follows_cross_origin_redirect_or_accepts_cookie(self):
        hits = {"external": 0}

        class External(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_GET(self) -> None:
                hits["external"] += 1
                self.send_response(200)
                self.send_header("Set-Cookie", "stolen=session")
                self.end_headers()

        external = ThreadingHTTPServer(("127.0.0.1", 0), External)
        external_thread = threading.Thread(target=external.serve_forever, daemon=True)
        external_thread.start()

        class ReauthRedirect(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_POST(self) -> None:
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{external.server_port}/cookie")
                self.end_headers()

        auth_server = ThreadingHTTPServer(("127.0.0.1", 0), ReauthRedirect)
        auth_thread = threading.Thread(target=auth_server.serve_forever, daemon=True)
        auth_thread.start()
        try:
            sys.path.insert(0, str(ROOT / "assets" / "python-mcp"))
            from website_mcp.auth import AuthSession

            session = AuthSession(
                {"modes": [{"id": "session", "kind": "cookie-session", "reauth": {"path": "/session", "method": "POST"}}]},
                f"http://127.0.0.1:{auth_server.server_port}",
            )
            self.assertFalse(session.reauthenticate(["session"]))
            self.assertEqual(hits["external"], 0)
        finally:
            sys.path = [item for item in sys.path if item != str(ROOT / "assets" / "python-mcp")]
            auth_server.shutdown()
            auth_thread.join(timeout=3)
            auth_server.server_close()
            external.shutdown()
            external_thread.join(timeout=3)
            external.server_close()

    def test_cli_stream_cap_and_env_executable_root_are_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cli-root"
            root.mkdir()
            script = root / "flood.py"
            script.write_text("import sys\nwhile True:\n sys.stdout.write('x' * 1024); sys.stdout.flush()\n", encoding="utf-8")
            sys.path.insert(0, str(ROOT / "assets" / "python-mcp"))
            from website_mcp.cli_adapter import CliAdapter

            config = {
                "io": {"cli_root_ref": "env:TEST_CLI_ROOT"}, "limits": {"max_output_bytes": 2048},
                "cli": {"commands": [{"id": "flood", "executable_ref": "env:TEST_CLI_EXEC", "argv": [], "arguments_schema": {"type": "object", "properties": {}, "additionalProperties": False}, "timeout_ms": 3000}]},
            }
            prior_root, prior_exec = os.environ.get("TEST_CLI_ROOT"), os.environ.get("TEST_CLI_EXEC")
            os.environ["TEST_CLI_ROOT"], os.environ["TEST_CLI_EXEC"] = str(root), str(script)
            try:
                started = time.monotonic()
                with self.assertRaisesRegex(ValueError, "cli_output_exceeds_byte_limit"):
                    CliAdapter(config).call("flood", {})
                self.assertLess(time.monotonic() - started, 2)
                os.environ["TEST_CLI_EXEC"] = "/bin/echo"
                with self.assertRaisesRegex(ValueError, "cli_executable_outside_root"):
                    CliAdapter(config).call("flood", {})
            finally:
                if prior_root is None:
                    os.environ.pop("TEST_CLI_ROOT", None)
                else:
                    os.environ["TEST_CLI_ROOT"] = prior_root
                if prior_exec is None:
                    os.environ.pop("TEST_CLI_EXEC", None)
                else:
                    os.environ["TEST_CLI_EXEC"] = prior_exec
                sys.path = [item for item in sys.path if item != str(ROOT / "assets" / "python-mcp")]

    def test_download_stays_under_configured_root(self):
        with tempfile.TemporaryDirectory() as tmp, fixture_site("public_catalog") as base:
            project, generated = Path(tmp) / "project", Path(tmp) / "generated"
            public_catalog_workspace(project, str(base))
            result = subprocess.run([sys.executable, str(GENERATOR), str(project), str(generated)], text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            root, outside = Path(tmp) / "downloads", Path(tmp) / "outside.pdf"
            root.mkdir()
            server = self.start_server(generated, env={**os.environ, "WEBSITE_MCP_DOWNLOAD_ROOT": str(root)})
            try:
                self.rpc(server, 1, "initialize", {"protocolVersion": "2025-06-18"})
                escaped = self.rpc(server, 2, "tools/call", {"name": "execute_capability", "arguments": {"capability_id": "products.manual", "arguments": {"id": "p-1", "download_path": str(outside)}}})
                self.assertEqual(escaped["error"]["message"], "download_path_outside_root")
                self.assertFalse(outside.exists())
            finally:
                self.stop_server(server)

    def test_http_redirects_are_refused_before_following(self):
        class Redirect(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_GET(self) -> None:
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:9/other")
                self.end_headers()

        listener = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
        thread = threading.Thread(target=listener.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                base = f"http://127.0.0.1:{listener.server_port}"
                project, generated = Path(tmp) / "project", Path(tmp) / "generated"
                public_catalog_workspace(project, base)
                result = subprocess.run([sys.executable, str(GENERATOR), str(project), str(generated)], text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                server = self.start_server(generated)
                try:
                    self.rpc(server, 1, "initialize", {"protocolVersion": "2025-06-18"})
                    redirected = self.rpc(server, 2, "tools/call", {"name": "execute_capability", "arguments": {"capability_id": "products.list", "arguments": {}}})
                    self.assertEqual(redirected["error"]["message"], "redirect_not_allowed")
                finally:
                    self.stop_server(server)
        finally:
            listener.shutdown()
            thread.join(timeout=3)
            listener.server_close()

    def test_generated_skill_contains_concrete_tool_examples(self):
        with tempfile.TemporaryDirectory() as tmp, fixture_site("public_catalog") as base:
            project, generated = Path(tmp) / "project", Path(tmp) / "generated"
            public_catalog_workspace(project, str(base))
            result = subprocess.run([sys.executable, str(GENERATOR), str(project), str(generated)], text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            skill = (generated / "skill" / "SKILL.md").read_text(encoding="utf-8")
            self.assertIn('describe_capabilities({"ids": ["products.list"]})', skill)
            self.assertIn('execute_capability({"capability_id": "products.list"', skill)
            self.assertIn("newline-delimited JSON-RPC over STDIO", skill)
            self.assertIn("protocolVersion 2025-06-18", skill)
            self.assertIn('"method":"initialize"', skill)

    def test_generated_skill_execute_example_skips_non_promoted_capabilities(self):
        with tempfile.TemporaryDirectory() as tmp, fixture_site("public_catalog") as base:
            project, generated = Path(tmp) / "project", Path(tmp) / "generated"
            public_catalog_workspace(project, str(base))
            workspace = project / ".website-mcp"
            graph = json.loads((workspace / "action-graph.json").read_text(encoding="utf-8"))
            graph["nodes"][0]["native"] = "candidate"
            write_json(workspace / "action-graph.json", graph)
            bind_promotion_evidence(workspace, "catalog-contract", graph["nodes"])
            coverage = json.loads((workspace / "coverage.json").read_text(encoding="utf-8"))
            coverage["action_counts"] = {"observed": 2, "native": 1, "verified": 2}
            coverage["gaps"] = [{"id": "products-list-not-promoted", "capability": "products.list", "impact": "test candidate", "evidence": ["catalog-contract"], "workaround": "use promoted manual", "owner": "test", "disposition": "unsupported"}]
            write_json(workspace / "coverage.json", coverage)
            result = subprocess.run([sys.executable, str(GENERATOR), str(project), str(generated)], text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            skill = (generated / "skill" / "SKILL.md").read_text(encoding="utf-8")
            self.assertIn('execute_capability({"capability_id": "products.manual"', skill)
            self.assertNotIn('execute_capability({"capability_id": "products.list"', skill)

    def test_normal_read_result_over_budget_is_refused_without_large_mcp_payload(self):
        class LargeResponse(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: object) -> None:
                return

            def do_GET(self) -> None:
                body = json.dumps({"items": [{"detail": "x" * 9000}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        listener = ThreadingHTTPServer(("127.0.0.1", 0), LargeResponse)
        thread = threading.Thread(target=listener.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                project, generated = Path(tmp) / "project", Path(tmp) / "generated"
                public_catalog_workspace(project, f"http://127.0.0.1:{listener.server_port}")
                result = subprocess.run([sys.executable, str(GENERATOR), str(project), str(generated)], text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                server = self.start_server(generated)
                try:
                    self.rpc(server, 1, "initialize", {"protocolVersion": "2025-06-18"})
                    response = self.rpc(server, 2, "tools/call", {"name": "execute_capability", "arguments": {"capability_id": "products.list", "arguments": {}}})
                    self.assertEqual(response["error"]["message"], "response_exceeds_8192_bytes")
                    self.assertLess(len(json.dumps(response)), 4096)
                finally:
                    self.stop_server(server)
        finally:
            listener.shutdown()
            thread.join(timeout=3)
            listener.server_close()

    def test_clean_generated_session_workflow_covers_confirmed_crud_batch_imports_and_downloads(self):
        fixture_env = {"FIXTURE_ADMIN_USER": "fixture-admin", "FIXTURE_ADMIN_PASSWORD": "fixture-password"}
        with tempfile.TemporaryDirectory() as tmp, fixture_site("session_admin", fixture_env) as base:
            project, generated = Path(tmp) / "project", Path(tmp) / "generated"
            public_catalog_workspace(project, str(base))
            workspace = project / ".website-mcp"
            evidence = "catalog-contract"

            def operation(route: str, kind: str, operation_id: str, method: str, parameters: list[dict] | None = None, body: object | None = None) -> dict:
                value = {"operationId": operation_id, "security": [], "responses": {"200": {"description": "fixture"}}, "x-mcp": {"route": route, "type": kind, "surface": "http", "evidence": [evidence]}}
                if parameters:
                    value["parameters"] = parameters
                if body is not None:
                    value["requestBody"] = body
                return value

            path_id = {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
            idempotency = {"name": "Idempotency-Key", "in": "header", "required": True, "schema": {"type": "string"}}
            etag = {"name": "If-Match", "in": "header", "required": True, "schema": {"type": "string"}}
            item_schema = {"type": "object", "required": ["name", "quantity"], "properties": {"name": {"type": "string"}, "quantity": {"type": "integer"}}, "additionalProperties": False}
            patch_schema = {"type": "object", "properties": {"name": {"type": "string"}, "quantity": {"type": "integer"}}, "additionalProperties": False}
            json_item = {"content": {"application/json": {"schema": item_schema}}}
            json_patch = {"content": {"application/json": {"schema": patch_schema}}}
            json_batch = {"content": {"application/json": {"schema": {"type": "array", "maxItems": 20, "items": {"type": "object", "required": ["id", "quantity"], "properties": {"id": {"type": "string"}, "quantity": {"type": "integer"}}, "additionalProperties": False}}}}}
            csv_body = {"content": {"text/csv": {"schema": {"type": "string"}}}}
            paths = {
                "/api/items": {"get": operation("/api/items", "read", "items.list", "get"), "post": operation("/api/items", "create", "items.create", "post", [idempotency], json_item)},
                "/api/items/{id}": {"patch": operation("/api/items/{id}", "update", "items.update", "patch", [path_id, etag], json_patch), "delete": operation("/api/items/{id}", "delete", "items.delete", "delete", [path_id])},
                "/api/items/batch": {"post": operation("/api/items/batch", "action", "items.batch", "post", None, json_batch)},
                "/api/imports": {"post": operation("/api/imports", "upload", "imports.preview", "post", None, csv_body)},
                "/api/imports/{id}/commit": {"post": operation("/api/imports/{id}/commit", "action", "imports.commit", "post", [path_id])},
                "/api/imports/{id}/errors.csv": {"get": operation("/api/imports/{id}/errors.csv", "download", "imports.errors", "get", [path_id])},
                "/api/exports/items.csv": {"get": operation("/api/exports/items.csv", "download", "items.export", "get")},
            }
            write_json(workspace / "openapi.json", {"openapi": "3.1.0", "info": {"title": "Session", "version": "1"}, "servers": [{"url": str(base)}], "paths": paths})
            write_json(workspace / "auth.json", {"version": 2, "status": "verified", "secret_policy": "references-only", "evidence": [], "modes": [{"id": "session", "kind": "cookie-session", "secret_ref": "env:FIXTURE_SESSION_COOKIE", "header_name": "Cookie", "csrf_ref": "env:FIXTURE_CSRF", "csrf_header": "X-CSRF-Token", "reauth": {"path": "/session", "method": "POST", "body_env_ref": "env:FIXTURE_REAUTH_BODY", "csrf_response_field": "csrf"}, "evidence": []}]})
            effects = {"items.list": "read", "items.create": "write", "items.update": "write", "items.delete": "destructive", "items.batch": "write", "imports.preview": "write", "imports.commit": "write", "imports.errors": "read", "items.export": "read"}
            nodes = [{"id": identifier, "intent": identifier, "surface": "http", "operations": [identifier], "commands": [], "native": "yes", "execution": "batch" if identifier == "items.batch" else ("download-stream" if identifier in {"imports.errors", "items.export"} else "independent"), "auth": ["session"], "side_effect": side_effect, "confirmation": "explicit confirmation required" if side_effect not in {"read", "none"} else "none", "evidence": [evidence], "confidence": "verified"} for identifier, side_effect in effects.items()]
            write_json(workspace / "action-graph.json", {"version": 2, "nodes": nodes, "edges": []})
            bind_promotion_evidence(workspace, evidence, nodes)
            write_json(workspace / "cli.json", {"version": 2, "commands": []})
            write_json(workspace / "coverage.json", {"version": 2, "route_counts": {"observed": 9, "modeled": 9, "verified": 9}, "action_counts": {"observed": 9, "native": 9, "verified": 9}, "gaps": []})
            generated_result = subprocess.run([sys.executable, str(GENERATOR), str(project), str(generated)], text=True, capture_output=True, timeout=10)
            self.assertEqual(generated_result.returncode, 0, generated_result.stderr)
            upload_root, download_root = Path(tmp) / "uploads", Path(tmp) / "downloads"
            upload_root.mkdir(); download_root.mkdir()
            (upload_root / "valid.csv").write_text("name,quantity\nNails,4\n", encoding="utf-8")
            (upload_root / "invalid.csv").write_text("name,quantity\nBad,nope\n", encoding="utf-8")
            server = self.start_server(generated, env={**os.environ, "FIXTURE_SESSION_COOKIE": "fixture_session=expired", "FIXTURE_CSRF": "csrf-expired", "FIXTURE_REAUTH_BODY": json.dumps({"username": "fixture-admin", "password": "fixture-password"}), "WEBSITE_MCP_UPLOAD_ROOT": str(upload_root), "WEBSITE_MCP_DOWNLOAD_ROOT": str(download_root)})
            def call(identifier: int, capability: str, arguments: dict, confirmation: bool = False) -> object:
                payload = {"capability_id": capability, "arguments": arguments}
                if confirmation:
                    payload["confirmation"] = True
                response = self.rpc(server, identifier, "tools/call", {"name": "execute_capability", "arguments": payload})
                self.assertIn("result", response, response)
                return json.loads(response["result"]["content"][0]["text"])
            try:
                self.rpc(server, 1, "initialize", {"protocolVersion": "2025-06-18"})
                call(2, "items.list", {})
                created = call(3, "items.create", {"Idempotency-Key": "created", "body": {"name": "Hammer", "quantity": 2}}, True)
                updated = call(4, "items.update", {"id": created["id"], "If-Match": '"1"', "body": {"quantity": 3}}, True)
                self.assertEqual(updated["quantity"], 3)
                batch = call(5, "items.batch", {"body": [{"id": created["id"], "quantity": 4}]}, True)
                self.assertEqual(batch["results"][0]["status"], 200)
                self.assertTrue(call(6, "items.delete", {"id": created["id"]}, True)["deleted"])
                valid = call(7, "imports.preview", {"upload_path": "valid.csv"}, True)
                self.assertTrue(call(8, "imports.commit", {"id": valid["import_id"]}, True)["committed"])
                invalid = call(9, "imports.preview", {"upload_path": "invalid.csv"}, True)
                errors = call(10, "imports.errors", {"id": invalid["import_id"], "download_path": "errors.csv"})
                export = call(11, "items.export", {"download_path": "items.csv"})
                self.assertIn(b"invalid quantity", (download_root / "errors.csv").read_bytes())
                self.assertIn(b"Nails,4", (download_root / "items.csv").read_bytes())
                self.assertEqual(errors["size"], (download_root / "errors.csv").stat().st_size)
                self.assertEqual(export["size"], (download_root / "items.csv").stat().st_size)
            finally:
                self.stop_server(server)

    def test_clean_generated_hybrid_workflow_covers_events_asset_render_and_verify(self):
        with tempfile.TemporaryDirectory() as tmp, fixture_site("hybrid_cli") as base:
            project, generated = Path(tmp) / "project", Path(tmp) / "generated"
            public_catalog_workspace(project, str(base))
            workspace, evidence = project / ".website-mcp", "catalog-contract"
            path_id = {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
            asset_name = {"name": "name", "in": "path", "required": True, "schema": {"type": "string"}}
            event_limit = {"name": "limit", "in": "query", "schema": {"type": "integer", "maximum": 50}}
            def operation(route: str, kind: str, identifier: str, parameters: list[dict]) -> dict:
                return {"operationId": identifier, "security": [], "parameters": parameters, "responses": {"200": {"description": "fixture"}}, "x-mcp": {"route": route, "type": kind, "surface": "hybrid", "evidence": [evidence]}}
            write_json(workspace / "openapi.json", {"openapi": "3.1.0", "info": {"title": "Hybrid", "version": "1"}, "servers": [{"url": str(base)}], "paths": {"/api/projects/{id}/events": {"get": operation("/api/projects/{id}/events", "read", "projects.events", [path_id, event_limit])}, "/api/projects/{id}/assets/{name}": {"get": operation("/api/projects/{id}/assets/{name}", "download", "projects.asset", [path_id, asset_name])}}})
            commands = [
                {"id": "report.render", "executable_ref": "env:FIXTURE_CLI_EXECUTABLE", "argv": ["report", "render", "--project={project}", "--output={output}"], "version_evidence": evidence, "arguments_schema": {"type": "object", "required": ["project", "output"], "properties": {"project": {"type": "string", "pattern": "^p-[0-9]+$"}, "output": {"type": "string"}}, "additionalProperties": False}, "stdout_schema": {"type": "object"}, "exit_codes": {"0": "success"}, "side_effect": "write", "timeout_ms": 3000, "evidence": [evidence]},
                {"id": "report.verify", "executable_ref": "env:FIXTURE_CLI_EXECUTABLE", "argv": ["report", "verify", "--path={path}"], "version_evidence": evidence, "arguments_schema": {"type": "object", "required": ["path"], "properties": {"path": {"type": "string"}}, "additionalProperties": False}, "stdout_schema": {"type": "object"}, "exit_codes": {"0": "success"}, "side_effect": "read", "timeout_ms": 3000, "evidence": [evidence]},
            ]
            write_json(workspace / "cli.json", {"version": 2, "commands": commands})
            node = lambda identifier, operations, commands, effect, execution: {"id": identifier, "intent": identifier, "surface": "stdio" if commands else "http", "operations": operations, "commands": commands, "native": "yes", "execution": execution, "auth": ["anonymous"] if not commands else [], "side_effect": effect, "confirmation": "explicit confirmation required" if effect not in {"read", "none"} else "none", "evidence": [evidence], "confidence": "verified"}
            nodes = [node("projects.events", ["projects.events"], [], "read", "paginated"), node("projects.asset", ["projects.asset"], [], "read", "download-stream"), node("report.render", [], ["report.render"], "write", "independent"), node("report.verify", [], ["report.verify"], "read", "independent")]
            write_json(workspace / "action-graph.json", {"version": 2, "nodes": nodes, "edges": []})
            bind_promotion_evidence(workspace, evidence, nodes)
            write_json(workspace / "auth.json", {"version": 2, "status": "anonymous", "secret_policy": "references-only", "evidence": [], "modes": [{"id": "anonymous", "kind": "anonymous", "evidence": []}]})
            write_json(workspace / "coverage.json", {"version": 2, "route_counts": {"observed": 2, "modeled": 2, "verified": 2}, "action_counts": {"observed": 4, "native": 4, "verified": 4}, "gaps": []})
            result = subprocess.run([sys.executable, str(GENERATOR), str(project), str(generated)], text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            downloads, reports = Path(tmp) / "downloads", Path(tmp) / "reports"
            downloads.mkdir(); reports.mkdir()
            server = self.start_server(generated, env={**os.environ, "WEBSITE_MCP_DOWNLOAD_ROOT": str(downloads), "WEBSITE_MCP_CLI_ROOT": str(ROOT / "fixtures" / "hybrid_cli"), "FIXTURE_CLI_EXECUTABLE": str(ROOT / "fixtures" / "hybrid_cli" / "fixture_cli.py"), "FIXTURE_CLI_OUTPUT_ROOT": str(reports)})
            def call(number: int, capability: str, arguments: dict, confirmation: bool = False) -> object:
                value = {"capability_id": capability, "arguments": arguments}
                if confirmation: value["confirmation"] = True
                response = self.rpc(server, number, "tools/call", {"name": "execute_capability", "arguments": value})
                self.assertIn("result", response, response)
                return json.loads(response["result"]["content"][0]["text"])
            try:
                self.rpc(server, 1, "initialize", {"protocolVersion": "2025-06-18"})
                events = call(2, "projects.events", {"id": "p-1", "limit": 1})
                self.assertEqual(events["items"][0]["id"], "e-1")
                asset = call(3, "projects.asset", {"id": "p-1", "name": "brief.txt", "download_path": "brief.txt"})
                self.assertEqual((downloads / "brief.txt").read_text(), "Project One brief\n")
                rendered = call(4, "report.render", {"project": "p-1", "output": "report.json"}, True)
                self.assertTrue(Path(rendered["path"]).is_file())
                verified = call(5, "report.verify", {"path": rendered["path"]})
                self.assertTrue(verified["valid"])
                self.assertEqual(asset["size"], (downloads / "brief.txt").stat().st_size)
            finally:
                self.stop_server(server)

    def test_generator_rejects_native_cli_with_unresolved_relative_executable(self):
        with tempfile.TemporaryDirectory() as tmp, fixture_site("public_catalog") as base:
            project, generated = Path(tmp) / "project", Path(tmp) / "generated"
            public_catalog_workspace(project, str(base))
            workspace = project / ".website-mcp"
            command = {
                "id": "relative.cli", "executable_ref": "local/tool.py", "argv": ["--version"],
                "version_evidence": "catalog-contract", "arguments_schema": {"type": "object", "properties": {}, "additionalProperties": False},
                "stdout_schema": {"type": "object"}, "exit_codes": {"0": "success"}, "side_effect": "read", "timeout_ms": 1000, "evidence": ["catalog-contract"],
            }
            write_json(workspace / "cli.json", {"version": 2, "commands": [command]})
            graph = json.loads((workspace / "action-graph.json").read_text(encoding="utf-8"))
            graph["nodes"].append({"id": "relative.cli", "intent": "Relative CLI", "surface": "stdio", "operations": [], "commands": ["relative.cli"], "native": "yes", "execution": "independent", "auth": [], "side_effect": "read", "confirmation": "none", "evidence": ["catalog-contract"], "confidence": "verified"})
            write_json(workspace / "action-graph.json", graph)
            bind_promotion_evidence(workspace, "catalog-contract", graph["nodes"])
            coverage = json.loads((workspace / "coverage.json").read_text(encoding="utf-8"))
            coverage["action_counts"] = {"observed": 3, "native": 3, "verified": 3}
            write_json(workspace / "coverage.json", coverage)
            result = subprocess.run([sys.executable, str(GENERATOR), str(project), str(generated)], text=True, capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("executable", result.stderr)


if __name__ == "__main__":
    unittest.main()
