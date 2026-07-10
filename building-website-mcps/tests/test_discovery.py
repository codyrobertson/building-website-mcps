import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from unittest.mock import patch

from fixture_harness import FIXTURES, fixture_site


SKILL_ROOT = Path(__file__).resolve().parents[1]
APPROVAL_KEY = "website-mcp-test-approval-key"
os.environ.setdefault("WEBSITE_MCP_APPROVAL_KEY", APPROVAL_KEY)
sys.path.insert(0, str(SKILL_ROOT / "scripts"))
from site_to_mcp.common import redact_text
from site_to_mcp.checkpoints import approved, checkpoint_hash
from site_to_mcp.compiler import Compiler

SCAFFOLD = SKILL_ROOT / "scripts" / "scaffold_workspace.py"
DISCOVER = SKILL_ROOT / "scripts" / "discover_target.py"
APPROVE = SKILL_ROOT / "scripts" / "approve_checkpoint.py"
VALIDATE = SKILL_ROOT / "scripts" / "validate_workspace.py"
TRANSITION = SKILL_ROOT / "scripts" / "transition_stage.py"


def run(*args: object, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *(str(arg) for arg in args)],
        capture_output=True,
        text=True,
        timeout=15,
        env=env or dict(os.environ),
    )


def json_lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


@contextmanager
def http_site(handler: type[BaseHTTPRequestHandler]):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


class DiscoveryCompilerTest(unittest.TestCase):
    def scaffold(self, project: str, target: str) -> Path:
        result = run(SCAFFOLD, project, target)
        self.assertEqual(result.returncode, 0, result.stderr)
        return Path(project) / ".website-mcp"

    def approve(self, project: str, checkpoint: str, artifact: str) -> None:
        result = run(
            APPROVE,
            project,
            checkpoint,
            "--decision",
            "approve",
            "--artifact",
            artifact,
            "--actor",
            "fixture-test",
            "--fixture-test",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def approve_remaining(self, project: str, *, auth: bool = False) -> None:
        if auth:
            self.approve(project, "auth", "auth.json")
        self.approve(project, "native-floor", "action-graph.json")
        self.approve(project, "final", "coverage.json")

    def approve_local(self, project: str | Path, checkpoint: str, artifact: str) -> None:
        result = run(
            APPROVE,
            project,
            checkpoint,
            "--decision",
            "approve",
            "--artifact",
            artifact,
            "--actor",
            f"local-uid:{os.getuid()}",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def approve_local_remaining(self, project: str | Path) -> None:
        self.approve_local(project, "native-floor", "action-graph.json")
        self.approve_local(project, "final", "coverage.json")

    def test_capture_redaction_removes_nested_json_credential_examples(self):
        redacted, fields = redact_text(
            '{"nested":{"password":"raw-password","access_token":"raw-token"}}'
        )
        self.assertNotIn("raw-password", redacted)
        self.assertNotIn("raw-token", redacted)
        self.assertIn("json-secret", fields)
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, "https://example.test")
            source = {
                "openapi": "3.1.0",
                "info": {"title": "secret example", "version": "1"},
                "components": {
                    "schemas": {"Login": {"example": {"password": "raw-password"}}}
                },
                "paths": {},
            }
            compiler = Compiler(Path(tmp), "https://example.test")
            evidence_id = compiler.capture(
                "https://example.test/openapi.json",
                200,
                {"Content-Type": "application/json"},
                json.dumps(source).encode(),
                "route-discovery",
            )
            compiler.compile(source, evidence_id, None)
            compiler.commit()
            self.assertNotIn("raw-password", (root / "openapi.json").read_text())

    def test_capture_redacts_container_secrets_headers_and_url_query_before_persistence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, "https://example.test")
            compiler = Compiler(Path(tmp), "https://example.test")
            payload = {
                "nested": {
                    "password": {"values": ["raw-password"]},
                    "access_token": ["raw-token"],
                }
            }
            evidence_id = compiler.capture(
                "https://example.test/openapi.json?token=raw-query",
                200,
                {
                    "Content-Type": "application/json",
                    "X-API-Key": "raw-api-key",
                    "Cookie": "session=raw-cookie",
                    "X-Trace": "Bearer raw-bearer-token",
                },
                json.dumps(payload).encode(),
                "route-discovery",
            )
            compiler.compile({"openapi": "3.1.0", "info": {"title": "x", "version": "1"}, "paths": {}}, evidence_id, None)
            compiler.commit()
            stored = json.loads((root / "evidence" / f"{evidence_id}.json").read_text())
            persisted = json.dumps(stored)
            for raw in ("raw-password", "raw-token", "raw-query", "raw-api-key", "raw-cookie", "raw-bearer-token"):
                self.assertNotIn(raw, persisted)
            self.assertEqual(stored["headers"]["X-API-Key"], "[REDACTED]")
            self.assertEqual(stored["headers"]["Cookie"], "[REDACTED]")
            self.assertEqual(stored["headers"]["X-Trace"], "[REDACTED]")
            with self.assertRaisesRegex(ValueError, "credential-free"):
                compiler.capture(
                    "https://user@example.test/openapi.json",
                    200,
                    {"Content-Type": "application/json"},
                    b"{}",
                    "route-discovery",
                )
            with self.assertRaisesRegex(ValueError, "credential-free"):
                compiler.capture(
                    "https://:password@example.test/openapi.json",
                    200,
                    {"Content-Type": "application/json"},
                    b"{}",
                    "route-discovery",
                )

    def test_sensitive_aliases_redact_nested_body_and_url_query_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, "https://example.test")
            source = {
                "openapi": "3.1.0",
                "info": {
                    "title": "aliases",
                    "version": "1",
                    "description": "https://example.test/callback?session_id=raw-query&api_key_value=raw-api-key",
                },
                "components": {
                    "examples": {
                        "capture": {
                            "value": {
                                "body": {
                                    "nested": {
                                        "session_id": "raw-session",
                                        "user_session_id": "raw-user-session",
                                        "api_key_value": ["raw-api-key"],
                                    }
                                }
                            }
                        }
                    }
                },
                "paths": {},
            }
            compiler = Compiler(Path(tmp), "https://example.test")
            evidence_id = compiler.capture(
                "https://example.test/openapi.json?session_id=raw-capture-query",
                200,
                {"Content-Type": "application/json"},
                json.dumps(source).encode(),
                "route-discovery",
            )
            compiler.compile(source, evidence_id, None)
            compiler.commit()
            persisted = "\n".join(
                path.read_text(encoding="utf-8")
                for path in root.rglob("*")
                if path.is_file()
            )
            for raw in (
                "raw-query",
                "raw-api-key",
                "raw-session",
                "raw-user-session",
                "raw-capture-query",
            ):
                self.assertNotIn(raw, persisted)

    def test_discovery_never_follows_cross_origin_redirects(self):
        outbound_requests: list[str] = []

        class ExternalHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                outbound_requests.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"<html>external</html>")

            def log_message(self, format: str, *args: object) -> None:
                return

        with http_site(ExternalHandler) as external:
            class TargetHandler(BaseHTTPRequestHandler):
                def do_GET(self) -> None:
                    if self.path == "/":
                        self.send_response(302)
                        self.send_header("Location", external + "/internal-metadata")
                        self.end_headers()
                        return
                    if self.path == "/openapi.json":
                        body = json.dumps(
                            {
                                "openapi": "3.1.0",
                                "info": {"title": "safe", "version": "1"},
                                "paths": {},
                            }
                        ).encode()
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                        return
                    self.send_response(404)
                    self.end_headers()

                def log_message(self, format: str, *args: object) -> None:
                    return

            with http_site(TargetHandler) as target, tempfile.TemporaryDirectory() as tmp:
                self.scaffold(tmp, target)
                self.approve(tmp, "scope", "spec.md")
                discovered = run(DISCOVER, tmp, target)
                self.assertEqual(discovered.returncode, 3, discovered.stderr)
                self.assertEqual(outbound_requests, [])

    def test_checkpoint_rejects_untrusted_actor_wrong_artifact_and_invalid_specification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, "http://127.0.0.1:9876")
            wrong_artifact = run(
                APPROVE,
                tmp,
                "scope",
                "--decision",
                "approve",
                "--artifact",
                "auth.json",
                "--actor",
                "fixture-test",
                "--fixture-test",
            )
            self.assertEqual(wrong_artifact.returncode, 2)
            self.assertIn("expected artifact", wrong_artifact.stderr)
            untrusted = run(
                APPROVE,
                tmp,
                "scope",
                "--decision",
                "approve",
                "--artifact",
                "spec.md",
                "--actor",
                "not-a-trusted-local-actor",
                "--fixture-test",
            )
            self.assertEqual(untrusted.returncode, 2)
            self.assertIn("trusted", untrusted.stderr)
            (root / "spec.md").write_text("not a specification\n", encoding="utf-8")
            invalid_spec = run(
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
            self.assertEqual(invalid_spec.returncode, 2)
            self.assertIn("semantic", invalid_spec.stderr)

    def test_malformed_discovery_inputs_report_structured_errors_without_tracebacks(self):
        with fixture_site("public_catalog") as base, tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, base)
            self.approve(tmp, "scope", "spec.md")
            malformed_cli = Path(tmp) / "malformed-cli.json"
            malformed_cli.write_text("{not-json", encoding="utf-8")
            failed_cli = run(DISCOVER, tmp, base, "--cli-contract", malformed_cli)
            self.assertEqual(failed_cli.returncode, 2)
            self.assertNotIn("Traceback", failed_cli.stderr)
            cli_error = json.loads(failed_cli.stderr)
            self.assertEqual(cli_error["status"], "discovery_error")
            self.assertEqual(cli_error["error"]["code"], "malformed_cli")
            self.assertEqual(json_lines(root / "discovery-iterations.jsonl")[-1]["result"], "discovery_error")

        class MalformedOpenAPIHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path == "/":
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"<html></html>")
                    return
                if self.path == "/openapi.json":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b"{not-json")
                    return
                self.send_response(404)
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        with http_site(MalformedOpenAPIHandler) as target, tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, target)
            self.approve(tmp, "scope", "spec.md")
            failed_openapi = run(DISCOVER, tmp, target, "--openapi", "/openapi.json")
            self.assertEqual(failed_openapi.returncode, 2)
            self.assertNotIn("Traceback", failed_openapi.stderr)
            openapi_error = json.loads(failed_openapi.stderr)
            self.assertEqual(openapi_error["error"]["code"], "malformed_openapi")
            self.assertEqual(json_lines(root / "discovery-iterations.jsonl")[-1]["result"], "discovery_error")

        with tempfile.TemporaryDirectory() as tmp:
            self.scaffold(tmp, "https://example.test")
            compiler = Compiler(Path(tmp), "https://example.test")
            with patch.object(compiler, "capture_url", return_value=(200, b"<html>", "html-proof")):
                with patch("site_to_mcp.compiler.SurfaceParser.feed", side_effect=ValueError("bad html")):
                    with self.assertRaisesRegex(ValueError, "malformed HTML"):
                        compiler.observe(None)

    def test_non_object_openapi_path_item_is_structured_error_without_commit(self):
        class MalformedPathHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path == "/":
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"<html></html>")
                    return
                if self.path == "/openapi.json":
                    body = json.dumps(
                        {
                            "openapi": "3.1.0",
                            "info": {"title": "bad", "version": "1"},
                            "paths": {"/items": ["not-a-path-item"]},
                        }
                    ).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        with http_site(MalformedPathHandler) as target, tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, target)
            self.approve(tmp, "scope", "spec.md")
            before = (root / "openapi.json").read_bytes()
            failed = run(DISCOVER, tmp, target)
            self.assertEqual(failed.returncode, 2)
            self.assertEqual(json.loads(failed.stderr)["error"]["code"], "malformed_openapi")
            self.assertEqual((root / "openapi.json").read_bytes(), before)
            self.assertFalse((root / "evidence").exists())

    def test_checkpoint_ledger_rejects_hash_and_provenance_forgery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, "http://127.0.0.1:9876")
            self.approve(tmp, "scope", "spec.md")
            self.assertTrue(approved(root, "scope"))
            records = json_lines(root / "checkpoints.jsonl")
            records[0]["reason"] = "forged after approval"
            (root / "checkpoints.jsonl").write_text(
                "\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n",
                encoding="utf-8",
            )
            self.assertFalse(approved(root, "scope"))

        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, "http://127.0.0.1:9876")
            self.approve(tmp, "scope", "spec.md")
            records = json_lines(root / "checkpoints.jsonl")
            records[0]["actor_source"] = "caller:fixture-test"
            records[0]["hash"] = checkpoint_hash(records[0])
            (root / "checkpoints.jsonl").write_text(
                "\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n",
                encoding="utf-8",
            )
            self.assertFalse(approved(root, "scope"))

    def test_checkpoint_actor_must_match_local_actor_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.scaffold(tmp, "http://127.0.0.1:9876")
            forged = run(
                APPROVE,
                tmp,
                "scope",
                "--decision",
                "approve",
                "--artifact",
                "spec.md",
                "--actor",
                "workspace-owner",
            )
            self.assertEqual(forged.returncode, 2)
            self.assertIn("local actor", forged.stderr)
            trusted = run(
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
            self.assertEqual(trusted.returncode, 0, trusted.stderr)

    def test_checkpoint_signature_rejects_same_uid_ledger_forgery_and_missing_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, "http://127.0.0.1:9876")
            self.approve(tmp, "scope", "spec.md")
            record = json_lines(root / "checkpoints.jsonl")[0]
            self.assertIn("signature", record)
            record["reason"] = "forged by same uid"
            record["hash"] = checkpoint_hash(record)
            (root / "checkpoints.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
            self.assertFalse(approved(root, "scope"))

        with tempfile.TemporaryDirectory() as tmp:
            self.scaffold(tmp, "http://127.0.0.1:9876")
            without_key = dict(os.environ)
            without_key.pop("WEBSITE_MCP_APPROVAL_KEY", None)
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
                env=without_key,
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("WEBSITE_MCP_APPROVAL_KEY", rejected.stderr)

    def test_discovery_redacts_javascript_and_html_sensitive_identifier_assignments(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, "https://example.test")
            compiler = Compiler(Path(tmp), "https://example.test")
            body = (
                b'<script>const clientSecret = "raw-client-secret"; '
                b'let sessionId = "raw-session-id";</script>'
                b'<input api_key_value="raw-api-key">'
            )
            evidence_id = compiler.capture(
                "https://example.test/page",
                200,
                {"Content-Type": "text/html"},
                body,
                "route-discovery",
            )
            source = {"openapi": "3.1.0", "info": {"title": "x", "version": "1"}, "paths": {}}
            compiler.compile(source, evidence_id, None)
            compiler.commit()
            persisted = (root / "evidence" / f"{evidence_id}.json").read_text(encoding="utf-8")
            for raw in ("raw-client-secret", "raw-session-id", "raw-api-key"):
                self.assertNotIn(raw, persisted)

    def test_discovery_redacts_quoted_identifier_assignments_with_spaces_and_escapes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, "https://example.test")
            compiler = Compiler(Path(tmp), "https://example.test")
            body = (
                b'<script>const clientSecret = "raw client \\"secret\\""; '
                b"let sessionId = 'raw session id';</script>"
            )
            evidence_id = compiler.capture(
                "https://example.test/page",
                200,
                {"Content-Type": "text/html"},
                body,
                "route-discovery",
            )
            source = {"openapi": "3.1.0", "info": {"title": "x", "version": "1"}, "paths": {}}
            compiler.compile(source, evidence_id, None)
            compiler.commit()
            persisted = (root / "evidence" / f"{evidence_id}.json").read_text(encoding="utf-8")
            self.assertNotIn("raw client", persisted)
            self.assertNotIn("raw session id", persisted)

    def test_credential_target_is_rejected_before_workspace_iteration_or_scaffold(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, "https://example.test")
            before = {
                str(path.relative_to(root)): path.read_bytes()
                for path in root.rglob("*")
                if path.is_file()
            }
            rejected = run(DISCOVER, tmp, "https://user:password@example.test")
            self.assertEqual(rejected.returncode, 2)
            self.assertEqual(json.loads(rejected.stderr)["error"]["code"], "unsafe_discovery_url")
            after = {
                str(path.relative_to(root)): path.read_bytes()
                for path in root.rglob("*")
                if path.is_file()
            }
            self.assertEqual(after, before)

        with tempfile.TemporaryDirectory() as tmp:
            rejected = run(SCAFFOLD, tmp, "https://user:password@example.test")
            self.assertEqual(rejected.returncode, 2)
            self.assertFalse((Path(tmp) / ".website-mcp").exists())

    def test_non_list_operation_security_is_structured_error_without_commit(self):
        class MalformedSecurityHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path == "/":
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"<html></html>")
                    return
                if self.path == "/openapi.json":
                    body = json.dumps(
                        {
                            "openapi": "3.1.0",
                            "info": {"title": "bad", "version": "1"},
                            "paths": {
                                "/items": {
                                    "get": {
                                        "operationId": "items.list",
                                        "security": None,
                                        "responses": {"200": {"description": "ok"}},
                                    }
                                }
                            },
                        }
                    ).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_response(404)
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        with http_site(MalformedSecurityHandler) as target, tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, target)
            self.approve(tmp, "scope", "spec.md")
            before = (root / "openapi.json").read_bytes()
            rejected = run(DISCOVER, tmp, target)
            self.assertEqual(rejected.returncode, 2)
            self.assertEqual(json.loads(rejected.stderr)["error"]["code"], "malformed_openapi")
            self.assertEqual((root / "openapi.json").read_bytes(), before)
            self.assertFalse((root / "evidence").exists())

    def test_symlinked_workspace_and_evidence_are_refused_without_following(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, "http://127.0.0.1:9876")
            outside = Path(tmp) / "outside-workspace"
            root.rename(outside)
            os.symlink(outside, root)
            blocked = run(DISCOVER, tmp, "http://127.0.0.1:9876")
            self.assertEqual(blocked.returncode, 2)
            self.assertEqual(json.loads(blocked.stderr)["error"]["code"], "unsafe_workspace")

        with fixture_site("public_catalog") as base, tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, base)
            self.approve(tmp, "scope", "spec.md")
            outside = Path(tmp) / "outside-evidence"
            outside.mkdir()
            os.symlink(outside, root / "evidence")
            blocked = run(DISCOVER, tmp, base)
            self.assertEqual(blocked.returncode, 2)
            self.assertEqual(list(outside.iterdir()), [])

    def test_malformed_evidence_index_returns_structured_error_without_commit(self):
        with fixture_site("public_catalog") as base, tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, base)
            self.approve(tmp, "scope", "spec.md")
            before = (root / "openapi.json").read_bytes()
            (root / "evidence-index.json").write_text("{broken", encoding="utf-8")
            failed = run(DISCOVER, tmp, base)
            self.assertEqual(failed.returncode, 2)
            self.assertEqual(json.loads(failed.stderr)["error"]["code"], "malformed_evidence_index")
            self.assertEqual((root / "openapi.json").read_bytes(), before)

    def test_commit_rejects_bad_managed_path_without_mixing_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, "https://example.test")
            compiler = Compiler(Path(tmp), "https://example.test")
            source = {"openapi": "3.1.0", "info": {"title": "x", "version": "1"}, "paths": {}}
            evidence_id = compiler.capture(
                "https://example.test/openapi.json",
                200,
                {"Content-Type": "application/json"},
                json.dumps(source).encode(),
                "route-discovery",
            )
            compiler.compile(source, evidence_id, None)
            original_openapi = (root / "openapi.json").read_bytes()
            outside = Path(tmp) / "outside-coverage.json"
            outside.write_text("outside", encoding="utf-8")
            (root / "coverage.json").unlink()
            os.symlink(outside, root / "coverage.json")
            with self.assertRaisesRegex(ValueError, "symlink"):
                compiler.commit()
            self.assertEqual((root / "openapi.json").read_bytes(), original_openapi)
            self.assertEqual(outside.read_text(encoding="utf-8"), "outside")
            self.assertFalse((root / "evidence").exists())

    def test_blocked_material_change_leaves_artifacts_state_and_approvals_untouched(self):
        with fixture_site("hybrid_cli") as base, tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, base)
            contract = Path(tmp) / "cli-contract.json"
            contract.write_bytes((FIXTURES / "hybrid_cli" / "cli-contract.json").read_bytes())
            self.approve(tmp, "scope", "spec.md")
            self.assertEqual(run(DISCOVER, tmp, base, "--cli-contract", contract).returncode, 3)
            self.approve_remaining(tmp)
            evidence_id = json.loads((root / "evidence-index.json").read_text())["records"][0]["id"]
            self.assertEqual(run(TRANSITION, tmp, "authorize", "complete", "--evidence", evidence_id).returncode, 0)
            for stage in ("discover", "model"):
                self.assertEqual(run(TRANSITION, tmp, stage, "in_progress").returncode, 0)
                self.assertEqual(run(TRANSITION, tmp, stage, "complete", "--evidence", evidence_id).returncode, 0)
            self.assertEqual(run(TRANSITION, tmp, "specify", "in_progress").returncode, 0)
            before = {
                str(path.relative_to(root)): path.read_bytes()
                for path in root.rglob("*")
                if path.is_file()
            }
            document = json.loads(contract.read_text())
            document["commands"][0]["timeout_ms"] += 1
            contract.write_text(json.dumps(document), encoding="utf-8")

            blocked = run(DISCOVER, tmp, base, "--cli-contract", contract)
            self.assertEqual(blocked.returncode, 2)
            self.assertIn("downstream stages are active", blocked.stderr)
            after = {
                str(path.relative_to(root)): path.read_bytes()
                for path in root.rglob("*")
                if path.is_file()
            }
            self.assertEqual(after, before)

    def test_external_openapi_refs_are_omitted_and_recorded_as_explicit_gaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, "https://example.test")
            source = {
                "openapi": "3.1.0",
                "info": {"title": "unsupported ref", "version": "1"},
                "paths": {
                    "/items": {
                        "get": {
                            "operationId": "items.list",
                            "security": [],
                            "responses": {"200": {"$ref": "https://other.test/response.json"}},
                        }
                    }
                },
            }
            compiler = Compiler(Path(tmp), "https://example.test")
            evidence_id = compiler.capture(
                "https://example.test/openapi.json",
                200,
                {"Content-Type": "application/json"},
                json.dumps(source).encode(),
                "route-discovery",
            )
            compiler.compile(source, evidence_id, None)
            compiler.commit()
            normalized = json.loads((root / "openapi.json").read_text())
            response = normalized["paths"]["/items"]["get"]["responses"]["200"]
            self.assertNotIn("$ref", response)
            gaps = json.loads((root / "coverage.json").read_text())["gaps"]
            self.assertIn("external", gaps[0]["impact"].lower())
            self.assertEqual(run(VALIDATE, tmp, "--level", "build").returncode, 0)

    def test_default_stops_for_scope_then_public_catalog_builds_from_live_evidence(self):
        with fixture_site("public_catalog") as base, tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, base)

            stopped = run(DISCOVER, tmp, base)
            self.assertEqual(stopped.returncode, 3)
            self.assertIn("scope", stopped.stdout)
            waiting = json_lines(root / "discovery-iterations.jsonl")[-1]
            self.assertEqual(waiting["result"], "awaiting_checkpoint")
            self.assertTrue(waiting["hypothesis"])
            self.assertTrue(waiting["planned_observations"])

            self.approve(tmp, "scope", "spec.md")
            discovered = run(DISCOVER, tmp, base)
            self.assertEqual(discovered.returncode, 3, discovered.stderr)
            self.assertIn("native-floor", discovered.stdout)
            document = json.loads((root / "openapi.json").read_text())
            self.assertIn("/api/products", document["paths"])
            marker = document["paths"]["/api/products"]["get"]["x-mcp"]
            self.assertEqual(
                {key: marker[key] for key in ("route", "type", "surface")},
                {"route": "/api/products", "type": "read", "surface": "hybrid"},
            )
            self.assertTrue(marker["evidence"])
            records = json.loads((root / "evidence-index.json").read_text())["records"]
            self.assertGreaterEqual(len(records), 3)
            for record in records:
                artifact = root / record["artifact"]
                self.assertTrue(artifact.is_file())
                self.assertNotIn("Authorization", artifact.read_text(encoding="utf-8"))
            iteration = json_lines(root / "discovery-iterations.jsonl")[-1]
            self.assertIn(iteration["result"], {"confirmed", "partial", "refuted"})
            self.assertTrue(iteration["evidence"])
            self.assertTrue(iteration["model_changes"])
            self.assertTrue(iteration["next_probe"])

            self.approve_remaining(tmp)
            complete = run(DISCOVER, tmp, base)
            self.assertEqual(complete.returncode, 0, complete.stderr)
            valid = run(VALIDATE, tmp, "--level", "build")
            self.assertEqual(valid.returncode, 0, valid.stderr)

    def test_cli_only_target_requires_safe_contract_and_never_models_http(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            root = self.scaffold(str(project), "cli://local")
            contract = Path(tmp) / "cli-contract.json"
            contract.write_bytes((FIXTURES / "hybrid_cli" / "cli-contract.json").read_bytes())

            self.approve_local(project, "scope", "spec.md")
            missing_contract = run(DISCOVER, project, "cli://local")
            self.assertEqual(missing_contract.returncode, 2)
            self.assertIn("--cli-contract", missing_contract.stderr)

            unsafe_contract = Path(tmp) / "unsafe-cli-contract.json"
            unsafe_contract.write_text(
                json.dumps(
                    {
                        "execution": {"mode": "argv", "shell": False, "executable_ref": "/tmp/not-allowlisted"},
                        "commands": [],
                    }
                ),
                encoding="utf-8",
            )
            rejected_contract = run(DISCOVER, project, "cli://local", "--cli-contract", unsafe_contract)
            self.assertEqual(rejected_contract.returncode, 2)
            self.assertIn("executable_ref is unsafe", rejected_contract.stderr)
            self.assertFalse((root / "evidence").exists())

            discovered = run(DISCOVER, project, "cli://local", "--cli-contract", contract)
            self.assertEqual(discovered.returncode, 3, discovered.stderr)
            self.assertIn("native-floor", discovered.stdout)

            openapi = json.loads((root / "openapi.json").read_text(encoding="utf-8"))
            self.assertEqual(openapi["openapi"], "3.1.0")
            self.assertEqual(openapi["paths"], {})
            self.assertEqual(openapi.get("servers", []), [])

            cli = json.loads((root / "cli.json").read_text(encoding="utf-8"))
            self.assertEqual(
                [command["id"] for command in cli["commands"]],
                ["project.inspect", "report.render", "report.verify"],
            )
            graph = json.loads((root / "action-graph.json").read_text(encoding="utf-8"))
            self.assertTrue(graph["nodes"])
            self.assertTrue(all(node["surface"] == "stdio" for node in graph["nodes"]))
            self.assertTrue(all(node["operations"] == [] for node in graph["nodes"]))
            self.assertTrue(all(node["native"] == "candidate" for node in graph["nodes"]))
            coverage = json.loads((root / "coverage.json").read_text(encoding="utf-8"))
            self.assertEqual(coverage["route_counts"], {"observed": 0, "modeled": 0, "verified": 0})
            self.assertEqual(coverage["action_counts"]["observed"], 3)
            self.assertEqual(run(VALIDATE, project, "--level", "build").returncode, 0)

            self.approve_local_remaining(project)
            confirmed = run(DISCOVER, project, "cli://local", "--cli-contract", contract)
            self.assertEqual(confirmed.returncode, 0, confirmed.stderr)

    def test_cli_targets_reject_userinfo_and_raw_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            for target in ("cli://user@local", "cli://local/raw-path", "cli:///raw-path", "cli://local:9000"):
                result = run(SCAFFOLD, Path(tmp) / target.replace(":", "-").replace("/", "-"), target)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("credential-free CLI target", result.stderr)

    def test_session_site_requires_explicit_auth_checkpoint_without_credentials(self):
        env = {
            "FIXTURE_ADMIN_USER": "fixture-admin",
            "FIXTURE_ADMIN_PASSWORD": "fixture-password",
        }
        with fixture_site("session_admin", env) as base, tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, base)
            self.approve(tmp, "scope", "spec.md")

            discovered = run(DISCOVER, tmp, base)
            self.assertEqual(discovered.returncode, 3, discovered.stderr)
            self.assertIn("auth", discovered.stdout)
            auth = json.loads((root / "auth.json").read_text())
            self.assertEqual(auth["status"], "observed")
            self.assertEqual(auth["modes"][0]["kind"], "cookie-session")
            all_artifacts = "\n".join(
                path.read_text(encoding="utf-8")
                for path in root.rglob("*")
                if path.is_file() and path.suffix in {".json", ".jsonl", ".txt"}
            )
            self.assertNotIn("fixture-password", all_artifacts)

            self.approve_remaining(tmp, auth=True)
            complete = run(DISCOVER, tmp, base)
            self.assertEqual(complete.returncode, 0, complete.stderr)
            self.assertEqual(run(VALIDATE, tmp, "--level", "build").returncode, 0)

    def test_hybrid_partial_spec_and_typed_cli_produce_explicit_gaps(self):
        contract = FIXTURES / "hybrid_cli" / "cli-contract.json"
        with fixture_site("hybrid_cli") as base, tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, base)
            self.approve(tmp, "scope", "spec.md")

            discovered = run(DISCOVER, tmp, base, "--cli-contract", contract)
            self.assertEqual(discovered.returncode, 3, discovered.stderr)
            cli = json.loads((root / "cli.json").read_text())
            self.assertEqual(
                [command["id"] for command in cli["commands"]],
                ["project.inspect", "report.render", "report.verify"],
            )
            self.assertEqual(
                cli["commands"][0]["argv"],
                ["project", "inspect", "--id", "{id}"],
            )
            graph = json.loads((root / "action-graph.json").read_text())
            self.assertTrue(any(node.get("commands") for node in graph["nodes"]))
            coverage = json.loads((root / "coverage.json").read_text())
            event_gap = next(
                gap for gap in coverage["gaps"] if "events" in gap["capability"]
            )
            records = {
                record["id"]: record
                for record in json.loads((root / "evidence-index.json").read_text())["records"]
            }
            self.assertTrue(
                records[event_gap["evidence"][0]]["source"].endswith("/static/project.js")
            )
            self.approve_remaining(tmp)
            complete = run(DISCOVER, tmp, base, "--cli-contract", contract)
            self.assertEqual(complete.returncode, 0, complete.stderr)
            valid = run(VALIDATE, tmp, "--level", "build")
            self.assertEqual(valid.returncode, 0, valid.stderr)

    def test_rejects_cross_origin_discovery_links(self):
        with fixture_site("public_catalog") as base, tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, base)
            self.approve(tmp, "scope", "spec.md")
            result = run(DISCOVER, tmp, base, "--openapi", "https://example.com/openapi.json")
            self.assertEqual(result.returncode, 2)
            self.assertIn("same-origin", result.stderr)
            self.assertFalse((root / "evidence").exists())

    def test_material_cli_evidence_change_invalidates_approvals_and_reopens_model(self):
        with fixture_site("hybrid_cli") as base, tempfile.TemporaryDirectory() as tmp:
            root = self.scaffold(tmp, base)
            contract = Path(tmp) / "cli-contract.json"
            contract.write_bytes((FIXTURES / "hybrid_cli" / "cli-contract.json").read_bytes())
            self.approve(tmp, "scope", "spec.md")
            self.assertEqual(run(DISCOVER, tmp, base, "--cli-contract", contract).returncode, 3)
            self.approve_remaining(tmp)
            evidence_id = json.loads((root / "evidence-index.json").read_text())["records"][0]["id"]
            self.assertEqual(
                run(TRANSITION, tmp, "authorize", "complete", "--evidence", evidence_id).returncode,
                0,
            )
            for stage in ("discover", "model"):
                self.assertEqual(run(TRANSITION, tmp, stage, "in_progress").returncode, 0)
                self.assertEqual(
                    run(TRANSITION, tmp, stage, "complete", "--evidence", evidence_id).returncode,
                    0,
                )
            document = json.loads(contract.read_text())
            document["commands"][0]["timeout_ms"] += 1
            contract.write_text(json.dumps(document), encoding="utf-8")

            changed = run(DISCOVER, tmp, base, "--cli-contract", contract)
            self.assertEqual(changed.returncode, 3, changed.stderr)
            self.assertIn("native-floor", changed.stdout)
            checkpoints = json_lines(root / "checkpoints.jsonl")
            latest = {record["checkpoint"]: record for record in checkpoints}
            self.assertEqual(latest["native-floor"]["decision"], "invalidated")
            self.assertEqual(latest["final"]["decision"], "invalidated")
            state = json.loads((root / "state.json").read_text())
            stages = {stage["id"]: stage for stage in state["stages"]}
            self.assertEqual(stages["discover"]["status"], "in_progress")
            self.assertEqual(stages["model"]["status"], "in_progress")
            self.assertEqual(run(VALIDATE, tmp).returncode, 0)


if __name__ == "__main__":
    unittest.main()
