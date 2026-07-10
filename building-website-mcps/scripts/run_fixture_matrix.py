#!/usr/bin/env python3
"""Run reproducible release evidence against every bundled website fixture.

This is an automated fixture matrix, not an agent evaluation.  It proves the
scaffold, approval, discovery, package, and STDIO discovery paths while keeping
fixture control credentials and process readiness values out of persisted
traces.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
from contextlib import ExitStack
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
SCAFFOLD = ROOT / "scripts" / "scaffold_workspace.py"
APPROVE = ROOT / "scripts" / "approve_checkpoint.py"
DISCOVER = ROOT / "scripts" / "discover_target.py"
VALIDATE = ROOT / "scripts" / "validate_workspace.py"
GENERATE = ROOT / "scripts" / "generate_mcp.py"
PROBE = ROOT / "scripts" / "mcp_probe.py"
RECORD_E2E = ROOT / "scripts" / "record_e2e_proof.py"
PROMOTE = ROOT / "scripts" / "promote_capabilities.py"

SITES = ("public_catalog", "session_admin", "hybrid_cli")
SENSITIVE_KEY = re.compile(
    r"(?:^|[_-])(?:password|token|secret|authorization|cookie|api[_-]?key)(?:$|[_-](?:value|id)$)",
    re.I,
)
SENSITIVE_INLINE = re.compile(
    r"(?i)\b(password|token|secret|authorization|cookie|api[_-]?key)\b([:=\s]+)([^\s,;\]\}\"]+)"
)


# Each command is deliberately an ordinary, explicit subprocess proof.  The
# recorder stores only its digest and bounded outcome, never argv or output.
# This keeps fixture credentials out of evidence while requiring the real
# fixture HTTP/CLI side effect before promotion.
FIXTURE_E2E_COMMAND = r'''
import json, os, subprocess, sys
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

base, case = sys.argv[1:]

def request(path, method="GET", value=None, headers=None, raw=False):
    body = value if isinstance(value, bytes) else (json.dumps(value).encode() if value is not None else None)
    merged = dict(headers or {})
    if value is not None and not isinstance(value, bytes):
        merged.setdefault("Content-Type", "application/json")
    try:
        with urlopen(Request(base + path, data=body, method=method, headers=merged), timeout=5) as response:
            return response.status, dict(response.headers), response.read()
    except HTTPError as error:
        return error.code, dict(error.headers), error.read()

def session_headers():
    status, headers, raw = request("/session", "POST", {
        "username": os.environ["FIXTURE_ADMIN_USER"],
        "password": os.environ["FIXTURE_ADMIN_PASSWORD"],
    })
    assert status == 200
    cookie = headers["Set-Cookie"].split(";", 1)[0]
    csrf = json.loads(raw)["csrf"]
    return {"Cookie": cookie, "X-CSRF-Token": csrf}

def cli(*arguments):
    completed = subprocess.run(
        [sys.executable, os.environ["FIXTURE_CLI_EXECUTABLE"], *arguments],
        text=True, capture_output=True, timeout=5,
    )
    assert completed.returncode == 0
    return json.loads(completed.stdout)

if case == "public-list":
    status, _headers, raw = request("/api/products?limit=1")
    assert status == 200 and json.loads(raw)["items"][0]["id"] == "p-1"
elif case == "public-manual":
    status, _headers, raw = request("/api/products/p-1/manual")
    assert status == 200 and raw.startswith(b"%PDF-fixture")
elif case.startswith("session-"):
    headers = session_headers()
    if case == "session-list":
        status, _headers, raw = request("/api/items", headers=headers)
        assert status == 200 and json.loads(raw)["items"]
    elif case == "session-create":
        status, _headers, raw = request("/api/items", "POST", {"name": "Proof create", "quantity": 2}, {**headers, "Idempotency-Key": "proof-create"})
        assert status == 201 and json.loads(raw)["id"].startswith("i-")
    elif case == "session-get":
        status, _headers, raw = request("/api/items/i-1", headers=headers)
        assert status == 200 and json.loads(raw)["id"] == "i-1"
    elif case == "session-update":
        status, _headers, raw = request("/api/items/i-1", "PATCH", {"quantity": 2}, {**headers, "If-Match": '"1"'})
        assert status == 200 and json.loads(raw)["quantity"] == 2
    elif case == "session-delete":
        status, _headers, raw = request("/api/items", "POST", {"name": "Proof delete", "quantity": 1}, {**headers, "Idempotency-Key": "proof-delete"})
        assert status == 201
        status, _headers, raw = request("/api/items/" + json.loads(raw)["id"], "DELETE", headers=headers)
        assert status == 200 and json.loads(raw)["deleted"] is True
    elif case == "session-batch":
        status, _headers, raw = request("/api/items/batch", "POST", [{"id": "i-1", "quantity": 3}], headers)
        assert status == 200 and json.loads(raw)["results"][0]["status"] == 200
    elif case == "session-preview":
        status, _headers, raw = request("/api/imports", "POST", b"name,quantity\nNails,4\n", headers)
        assert status == 200 and json.loads(raw)["valid_count"] == 1
    elif case == "session-commit":
        status, _headers, raw = request("/api/imports", "POST", b"name,quantity\nNails,4\n", headers)
        assert status == 200
        status, _headers, raw = request("/api/imports/" + json.loads(raw)["import_id"] + "/commit", "POST", headers=headers)
        assert status == 200 and json.loads(raw)["committed"] is True
    elif case == "session-errors":
        status, _headers, raw = request("/api/imports", "POST", b"name,quantity\nBad,nope\n", headers)
        assert status == 200
        status, _headers, raw = request("/api/imports/" + json.loads(raw)["import_id"] + "/errors.csv", headers=headers)
        assert status == 200 and b"invalid quantity" in raw
    elif case == "session-export":
        status, _headers, raw = request("/api/exports/items.csv", headers=headers)
        assert status == 200 and raw.startswith(b"id,name,quantity")
    else:
        raise AssertionError(case)
elif case == "hybrid-http":
    status, _headers, raw = request("/api/projects/p-1")
    assert status == 200 and json.loads(raw)["id"] == "p-1"
elif case == "hybrid-inspect":
    assert cli("project", "inspect", "--id", "p-1")["id"] == "p-1"
elif case == "hybrid-render":
    output = str(Path(os.environ["FIXTURE_CLI_OUTPUT_ROOT"]) / "proof-render.json")
    assert Path(cli("report", "render", "--project", "p-1", "--output", output)["path"]).is_file()
elif case == "hybrid-verify":
    output = str(Path(os.environ["FIXTURE_CLI_OUTPUT_ROOT"]) / "proof-render.json")
    if not Path(output).exists():
        cli("report", "render", "--project", "p-1", "--output", output)
    assert cli("report", "verify", "--path", output)["valid"] is True
else:
    raise AssertionError(case)

print(json.dumps({"status": "ok", "case": case}, sort_keys=True))
'''


E2E_CASES = {
    "public_catalog": (("products.list", "public-list"), ("products.manual", "public-manual")),
    "session_admin": (
        ("items.list", "session-list"),
        ("items.create", "session-create"),
        ("items.get", "session-get"),
        ("items.update", "session-update"),
        ("items.delete", "session-delete"),
        ("items.batch", "session-batch"),
        ("imports.preview", "session-preview"),
        ("imports.commit", "session-commit"),
        ("imports.errors", "session-errors"),
        ("items.export", "session-export"),
    ),
    "hybrid_cli": (
        ("projects.get", "hybrid-http"),
        ("project.inspect", "hybrid-inspect"),
        ("report.render", "hybrid-render"),
        ("report.verify", "hybrid-verify"),
    ),
}


class EvidenceError(RuntimeError):
    """A matrix step did not produce its required proof."""


def redact_value(value: Any) -> Any:
    """Return a display-safe value without mutating the source trace object."""
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if SENSITIVE_KEY.search(str(key)) else redact_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, (dict, list)):
            return json.dumps(redact_value(parsed), sort_keys=True)
        return SENSITIVE_INLINE.sub(r"\1\2[REDACTED]", value)
    return value


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(redact_value(value), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _line_from(stream: Any, timeout: float) -> str:
    lines: queue.Queue[str] = queue.Queue(maxsize=1)
    threading.Thread(target=lambda: lines.put(stream.readline()), daemon=True).start()
    try:
        return lines.get(timeout=timeout)
    except queue.Empty as exc:
        raise EvidenceError(f"fixture readiness timeout after {timeout:g} seconds") from exc


class FixtureProcess:
    def __init__(self, site: str) -> None:
        self.site = site
        self.process: subprocess.Popen[str] | None = None
        self.base_url: str | None = None

    def start(self) -> "FixtureProcess":
        env = dict(os.environ)
        if self.site == "session_admin":
            env.update({"FIXTURE_ADMIN_USER": "fixture-admin", "FIXTURE_ADMIN_PASSWORD": "fixture-password"})
        script = FIXTURES / self.site / "app.py"
        self.process = subprocess.Popen(
            [sys.executable, str(script), "--port", "0"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        if self.process.stdout is None:
            raise EvidenceError(f"{self.site} fixture stdout is unavailable")
        line = _line_from(self.process.stdout, 5)
        if not line:
            stderr = self.process.stderr.read() if self.process.stderr else ""
            raise EvidenceError(f"{self.site} fixture did not become ready: {redact_value(stderr)}")
        try:
            readiness = json.loads(line)
            port = readiness["port"]
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise EvidenceError(f"{self.site} fixture emitted invalid readiness JSON") from exc
        if not isinstance(port, int) or not 0 < port < 65536:
            raise EvidenceError(f"{self.site} fixture readiness port is invalid")
        self.base_url = f"http://127.0.0.1:{port}"
        return self

    def close(self) -> None:
        if self.process is None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=3)
        for stream in (self.process.stdout, self.process.stderr):
            if stream:
                stream.close()


class StdioClient:
    def __init__(self, package: Path, *, env: dict[str, str] | None = None) -> None:
        self.package = package
        self.env = dict(env or os.environ)
        self.process: subprocess.Popen[str] | None = None
        self.identifier = 0

    def __enter__(self) -> "StdioClient":
        self.process = subprocess.Popen(
            [sys.executable, str(self.package / "server.py")],
            cwd=self.package,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**self.env, "PYTHONPATH": ""},
        )
        return self

    def request(self, method: str, params: dict[str, Any]) -> tuple[dict[str, Any], int]:
        if self.process is None or self.process.stdin is None or self.process.stdout is None:
            raise EvidenceError("STDIO client is not started")
        self.identifier += 1
        request = {"jsonrpc": "2.0", "id": self.identifier, "method": method, "params": params}
        self.process.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            stderr = self.process.stderr.read() if self.process.stderr else ""
            raise EvidenceError(f"STDIO server closed before {method}: {redact_value(stderr)}")
        try:
            response = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EvidenceError(f"STDIO server returned non-JSON for {method}") from exc
        if "error" in response:
            error = response.get("error", {})
            raise EvidenceError(f"STDIO {method} returned rpc error {error.get('code')}")
        return response, len(line.encode("utf-8"))

    def __exit__(self, *_: object) -> None:
        if self.process is None:
            return
        if self.process.stdin:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=3)
        for stream in (self.process.stdout, self.process.stderr):
            if stream:
                stream.close()


def command(
    arguments: list[str],
    trace: list[dict[str, Any]],
    *,
    expected: int | tuple[int, ...] = 0,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    started = time.monotonic()
    completed = subprocess.run(arguments, text=True, capture_output=True, timeout=20, env=dict(env or os.environ))
    trace.append(
        {
            "kind": "command",
            "program": Path(arguments[1]).name if len(arguments) > 1 else arguments[0],
            "returncode": completed.returncode,
            "duration_ms": round((time.monotonic() - started) * 1000, 3),
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    )
    expected_codes = (expected,) if isinstance(expected, int) else expected
    if completed.returncode not in expected_codes:
        raise EvidenceError(f"{Path(arguments[1]).name} exited {completed.returncode}; expected {expected_codes}")
    return completed


def approve(project: Path, checkpoint: str, artifact: str, trace: list[dict[str, Any]]) -> None:
    command(
        [
            sys.executable,
            str(APPROVE),
            str(project),
            checkpoint,
            "--decision",
            "approve",
            "--artifact",
            artifact,
            "--actor",
            "fixture-test",
            "--fixture-test",
        ],
        trace,
    )


def _checkpoint(result: subprocess.CompletedProcess[str]) -> str:
    try:
        value = json.loads(result.stdout)
        checkpoint = value["checkpoint"]
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise EvidenceError("discovery checkpoint response is malformed") from exc
    if checkpoint not in {"auth", "native-floor", "final"}:
        raise EvidenceError(f"unexpected discovery checkpoint: {checkpoint!r}")
    return checkpoint


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"{path.name} is malformed") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"{path.name} must be a JSON object")
    return value


def _capability_node(project: Path, capability_id: str) -> dict[str, Any]:
    graph = _load_json(project / ".website-mcp" / "action-graph.json")
    nodes = graph.get("nodes", [])
    matches = [node for node in nodes if isinstance(node, dict) and node.get("id") == capability_id]
    if len(matches) != 1:
        raise EvidenceError(f"fixture graph has no unique {capability_id!r} capability")
    return matches[0]


def _add_parameter(operation: dict[str, Any], parameter: dict[str, Any]) -> None:
    parameters = operation.setdefault("parameters", [])
    if not isinstance(parameters, list):
        raise EvidenceError("fixture operation parameters are malformed")
    if not any(
        isinstance(item, dict)
        and item.get("name") == parameter["name"]
        and item.get("in") == parameter["in"]
        for item in parameters
    ):
        parameters.append(parameter)


def _operation(openapi: dict[str, Any], operation_id: str) -> dict[str, Any]:
    paths = openapi.get("paths", {})
    if not isinstance(paths, dict):
        raise EvidenceError("fixture OpenAPI paths are malformed")
    for path_item in paths.values():
        if not isinstance(path_item, dict):
            continue
        for value in path_item.values():
            if isinstance(value, dict) and value.get("operationId") == operation_id:
                return value
    raise EvidenceError(f"fixture OpenAPI omits {operation_id!r}")


def _configure_fixture_execution_contract(site: str, project: Path, trace: list[dict[str, Any]]) -> None:
    """Add only fixture-known adapter details that discovery cannot infer from OpenAPI.

    These values are references and schemas, never credential values.  They are
    necessary for the generated package to replay the post-discovery fixture
    proof through STDIO rather than treating a direct fixture probe as MCP
    execution proof.
    """
    workspace = project / ".website-mcp"
    if site == "public_catalog":
        openapi = _load_json(workspace / "openapi.json")
        products = _operation(openapi, "products.list")
        for parameter in (
            {"name": "q", "in": "query", "schema": {"type": "string"}},
            {"name": "fields", "in": "query", "schema": {"type": "string"}},
            {"name": "cursor", "in": "query", "schema": {"type": "string"}},
            {"name": "limit", "in": "query", "schema": {"type": "integer", "maximum": 50}},
        ):
            _add_parameter(products, parameter)
        write_json(workspace / "openapi.json", openapi)
        trace.append(
            {
                "kind": "fixture_execution_contract",
                "site": site,
                "details": ["catalog_query_projection_parameters"],
            }
        )
    elif site == "session_admin":
        openapi = _load_json(workspace / "openapi.json")
        item_schema = {
            "type": "object",
            "required": ["name", "quantity"],
            "properties": {"name": {"type": "string"}, "quantity": {"type": "integer"}},
            "additionalProperties": False,
        }
        patch_schema = {
            "type": "object",
            "properties": {"name": {"type": "string"}, "quantity": {"type": "integer"}},
            "additionalProperties": False,
        }
        batch_schema = {
            "type": "array",
            "maxItems": 20,
            "items": {
                "type": "object",
                "required": ["id", "quantity"],
                "properties": {"id": {"type": "string"}, "quantity": {"type": "integer"}},
                "additionalProperties": False,
            },
        }
        create = _operation(openapi, "items.create")
        items_list = _operation(openapi, "items.list")
        _add_parameter(items_list, {"name": "cursor", "in": "query", "schema": {"type": "string"}})
        _add_parameter(items_list, {"name": "limit", "in": "query", "schema": {"type": "integer", "maximum": 50}})
        _add_parameter(
            create,
            {"name": "Idempotency-Key", "in": "header", "required": True, "schema": {"type": "string"}},
        )
        create["requestBody"] = {"content": {"application/json": {"schema": item_schema}}}
        update = _operation(openapi, "items.update")
        _add_parameter(
            update,
            {"name": "If-Match", "in": "header", "required": True, "schema": {"type": "string"}},
        )
        update["requestBody"] = {"content": {"application/json": {"schema": patch_schema}}}
        _operation(openapi, "items.batch")["requestBody"] = {
            "content": {"application/json": {"schema": batch_schema}}
        }
        _operation(openapi, "imports.preview")["requestBody"] = {
            "content": {"text/csv": {"schema": {"type": "string"}}}
        }
        write_json(workspace / "openapi.json", openapi)

        auth = _load_json(workspace / "auth.json")
        modes = auth.get("modes", [])
        if not isinstance(modes, list):
            raise EvidenceError("fixture auth modes are malformed")
        observed = next((mode for mode in modes if isinstance(mode, dict) and mode.get("id") == "observed-auth"), None)
        if observed is None:
            raise EvidenceError("fixture auth discovery did not yield observed-auth")
        observed.update(
            {
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
            }
        )
        write_json(workspace / "auth.json", auth)
        trace.append(
            {
                "kind": "fixture_execution_contract",
                "site": site,
                "details": ["cookie_reauthentication", "json_write_bodies", "csv_upload_body"],
            }
        )
    elif site == "hybrid_cli":
        cli = _load_json(workspace / "cli.json")
        commands = cli.get("commands", [])
        if not isinstance(commands, list):
            raise EvidenceError("fixture CLI commands are malformed")
        for item in commands:
            if isinstance(item, dict):
                item["executable_ref"] = "env:FIXTURE_CLI_EXECUTABLE"
        write_json(workspace / "cli.json", cli)
        trace.append(
            {
                "kind": "fixture_execution_contract",
                "site": site,
                "details": ["environment_referenced_cli_executable"],
            }
        )


def _execution_environment(site: str, site_root: Path) -> dict[str, str]:
    environment = dict(os.environ)
    downloads = site_root / "downloads"
    uploads = site_root / "uploads"
    cli_output = site_root / "cli-output"
    for directory in (downloads, uploads, cli_output):
        directory.mkdir(parents=True, exist_ok=True)
    environment.update(
        {
            "WEBSITE_MCP_DOWNLOAD_ROOT": str(downloads),
            "WEBSITE_MCP_UPLOAD_ROOT": str(uploads),
            "WEBSITE_MCP_CLI_ROOT": str(FIXTURES / "hybrid_cli"),
            "FIXTURE_CLI_EXECUTABLE": str(FIXTURES / "hybrid_cli" / "fixture_cli.py"),
            "FIXTURE_CLI_OUTPUT_ROOT": str(cli_output),
        }
    )
    if site == "session_admin":
        (uploads / "valid.csv").write_text("name,quantity\nNails,4\n", encoding="utf-8")
        (uploads / "invalid.csv").write_text("name,quantity\nBad,nope\n", encoding="utf-8")
        environment.update(
            {
                "FIXTURE_ADMIN_USER": "fixture-admin",
                "FIXTURE_ADMIN_PASSWORD": "fixture-password",
                "FIXTURE_SESSION_COOKIE": "fixture_session=expired",
                "FIXTURE_CSRF": "csrf-expired",
                "FIXTURE_REAUTH_BODY": json.dumps({"username": "fixture-admin", "password": "fixture-password"}),
            }
        )
    return environment


def _record_and_promote(
    site: str,
    project: Path,
    base_url: str,
    trace: list[dict[str, Any]],
    environment: dict[str, str],
) -> list[dict[str, Any]]:
    proofs: list[tuple[str, str, str, dict[str, Any]]] = []
    for capability_id, case in E2E_CASES[site]:
        node = _capability_node(project, capability_id)
        operations = node.get("operations")
        commands = node.get("commands", [])
        if not isinstance(operations, list) or not isinstance(commands, list):
            raise EvidenceError(f"fixture capability bindings are malformed: {capability_id}")
        evidence_id = f"fixture-{site}-{capability_id.replace('.', '-')}-e2e"
        recorded = command(
            [
                sys.executable,
                str(RECORD_E2E),
                str(project),
                capability_id,
                "--evidence-id",
                evidence_id,
                "--operations-json",
                json.dumps(operations, separators=(",", ":")),
                "--commands-json",
                json.dumps(commands, separators=(",", ":")),
                "--argv-json",
                json.dumps([sys.executable, "-c", FIXTURE_E2E_COMMAND, base_url, case]),
                "--fresh-for-seconds",
                "3600",
            ],
            trace,
            env=environment,
        )
        try:
            value = json.loads(recorded.stdout)
        except json.JSONDecodeError as exc:
            raise EvidenceError(f"E2E recorder returned invalid output for {capability_id}") from exc
        if value.get("status") != "recorded" or value.get("evidence_id") != evidence_id:
            raise EvidenceError(f"E2E recorder did not confirm {capability_id}")
        trace.append(
            {
                "kind": "e2e_proof",
                "capability_id": capability_id,
                "evidence_id": evidence_id,
                "operations": operations,
                "commands": commands,
                "side_effect": node.get("side_effect"),
                "case": case,
                "status": "recorded",
            }
        )
        proofs.append((capability_id, evidence_id, case, node))

    promotions: list[dict[str, Any]] = []
    for capability_id, evidence_id, case, node in proofs:
        promoted = command(
            [sys.executable, str(PROMOTE), str(project), capability_id, "--evidence", evidence_id],
            trace,
            env=environment,
        )
        try:
            value = json.loads(promoted.stdout)
        except json.JSONDecodeError as exc:
            raise EvidenceError(f"promotion returned invalid output for {capability_id}") from exc
        if value.get("status") != "promoted" or value.get("capability_id") != capability_id:
            raise EvidenceError(f"promotion did not confirm {capability_id}")
        item = {
            "capability_id": capability_id,
            "evidence_id": evidence_id,
            "case": case,
            "side_effect": node.get("side_effect"),
            "status": "promoted",
        }
        promotions.append(item)
        trace.append({"kind": "promotion", **item})
    return promotions


def _capability_trace(package: Path, trace: list[dict[str, Any]], environment: dict[str, str]) -> None:
    probe = command([sys.executable, str(PROBE), str(package)], trace)
    try:
        if json.loads(probe.stdout).get("status") != "ok":
            raise EvidenceError("clean STDIO probe did not report ok")
    except json.JSONDecodeError as exc:
        raise EvidenceError("clean STDIO probe returned invalid JSON") from exc
    with StdioClient(package, env=environment) as client:
        initialize, size = client.request("initialize", {"protocolVersion": "2025-06-18"})
        trace.append({"kind": "rpc", "method": "initialize", "response_bytes": size, "success": "result" in initialize})
        listed, size = client.request("tools/list", {})
        tools = listed.get("result", {}).get("tools", [])
        if not isinstance(tools, list) or size > 16 * 1024:
            raise EvidenceError("tools/list did not meet the 16KiB list budget")
        trace.append({"kind": "rpc", "method": "tools/list", "response_bytes": size, "success": True})
        searched, size = client.request("tools/call", {"name": "search_capabilities", "arguments": {"query": ""}})
        try:
            content = searched["result"]["content"][0]["text"]
            capabilities = json.loads(content)["capabilities"]
            capability_id = capabilities[0]["id"]
        except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise EvidenceError("search_capabilities did not return a capability") from exc
        if size > 4 * 1024:
            raise EvidenceError("search_capabilities exceeded its 4KiB response budget")
        trace.append({"kind": "rpc", "method": "search_capabilities", "response_bytes": size, "success": True})
        described, size = client.request("tools/call", {"name": "describe_capabilities", "arguments": {"ids": [capability_id]}})
        if "result" not in described or size > 8 * 1024:
            raise EvidenceError("describe_capabilities did not meet its 8KiB response budget")
        trace.append({"kind": "rpc", "method": "describe_capabilities", "response_bytes": size, "success": True})
        planned, size = client.request("tools/call", {"name": "plan_workflow", "arguments": {"capability_id": capability_id}})
        if "result" not in planned or size > 8 * 1024:
            raise EvidenceError("plan_workflow did not meet its 8KiB response budget")
        trace.append({"kind": "rpc", "method": "plan_workflow", "response_bytes": size, "success": True})


def _execute_capability(
    client: StdioClient,
    project: Path,
    trace: list[dict[str, Any]],
    scenario: str,
    capability_id: str,
    arguments: dict[str, Any],
    *,
    confirmation: bool = False,
) -> tuple[Any, int, str]:
    payload: dict[str, Any] = {"capability_id": capability_id, "arguments": arguments}
    if confirmation:
        payload["confirmation"] = True
    response, size = client.request("tools/call", {"name": "execute_capability", "arguments": payload})
    try:
        text = response["result"]["content"][0]["text"]
        value = json.loads(text)
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"execute_capability returned malformed content for {capability_id}") from exc
    side_effect = str(_capability_node(project, capability_id).get("side_effect", "read"))
    trace.append(
        {
            "kind": "capability_execution",
            "scenario": scenario,
            "capability_id": capability_id,
            "side_effect": side_effect,
            "response_bytes": size,
            "success": True,
        }
    )
    return value, size, side_effect


def _scenario_result(scenario: str, records: list[tuple[str, int, str]]) -> dict[str, Any]:
    effects = {effect for _capability, _size, effect in records}
    return {
        "scenario": scenario,
        "capabilities": [capability for capability, _size, _effect in records],
        # A scenario that includes a destructive fixture cleanup is still
        # reported as a write aggregate; each capability trace preserves the
        # exact side effect for auditing.
        "side_effect": "write" if effects - {"none", "read"} else "read",
        "side_effects": sorted(effects),
        "response_bytes": sum(size for _capability, size, _effect in records),
        "status": "ok",
    }


def _execute_promoted_capabilities(
    site: str,
    project: Path,
    package: Path,
    site_root: Path,
    trace: list[dict[str, Any]],
    environment: dict[str, str],
) -> list[dict[str, Any]]:
    """Execute the final generated artifact, not the direct E2E proof client."""
    reports: list[dict[str, Any]] = []
    downloads = site_root / "downloads"
    cli_output = site_root / "cli-output"
    with StdioClient(package, env=environment) as client:
        initialized, size = client.request("initialize", {"protocolVersion": "2025-06-18"})
        if "result" not in initialized:
            raise EvidenceError("generated server did not initialize for execution")
        trace.append({"kind": "rpc", "method": "initialize_execute", "response_bytes": size, "success": True})

        if site == "public_catalog":
            scenario = "public_list"
            listed, size, effect = _execute_capability(
                client,
                project,
                trace,
                scenario,
                "products.list",
                {"q": "red", "fields": "id,name,price", "limit": 1},
            )
            if not isinstance(listed, dict) or listed.get("items", [{}])[0].get("id") != "p-1":
                raise EvidenceError("promoted public list did not return the fixture product")
            reports.append(_scenario_result(scenario, [("products.list", size, effect)]))

            scenario = "public_manual"
            manual, size, effect = _execute_capability(
                client,
                project,
                trace,
                scenario,
                "products.manual",
                {"id": "p-1", "download_path": "public-manual.pdf"},
            )
            if not isinstance(manual, dict) or not (downloads / "public-manual.pdf").read_bytes().startswith(b"%PDF-fixture"):
                raise EvidenceError("promoted public manual did not download through STDIO")
            reports.append(_scenario_result(scenario, [("products.manual", size, effect)]))

        elif site == "session_admin":
            scenario = "session_auth_recovery"
            listed, size, effect = _execute_capability(
                client, project, trace, scenario, "items.list", {"limit": 1}
            )
            if not isinstance(listed, dict) or listed.get("items", [{}])[0].get("id") != "i-1":
                raise EvidenceError("session read did not recover authentication")
            reports.append(_scenario_result(scenario, [("items.list", size, effect)]))

            scenario = "session_crud"
            created, create_size, create_effect = _execute_capability(
                client,
                project,
                trace,
                scenario,
                "items.create",
                {"Idempotency-Key": "matrix-created", "body": {"name": "Matrix hammer", "quantity": 2}},
                confirmation=True,
            )
            if not isinstance(created, dict) or not isinstance(created.get("id"), str):
                raise EvidenceError("session create did not return an item ID")
            item_id = created["id"]
            read, read_size, read_effect = _execute_capability(
                client, project, trace, scenario, "items.get", {"id": item_id}
            )
            if not isinstance(read, dict) or read.get("id") != item_id:
                raise EvidenceError("session get did not return the created item")
            updated, update_size, update_effect = _execute_capability(
                client,
                project,
                trace,
                scenario,
                "items.update",
                {"id": item_id, "If-Match": f'"{created.get("version", 1)}"', "body": {"quantity": 3}},
                confirmation=True,
            )
            if not isinstance(updated, dict) or updated.get("quantity") != 3:
                raise EvidenceError("session update did not change the fixture item")
            deleted, delete_size, delete_effect = _execute_capability(
                client, project, trace, scenario, "items.delete", {"id": item_id}, confirmation=True
            )
            if not isinstance(deleted, dict) or deleted.get("deleted") is not True:
                raise EvidenceError("session delete did not remove the fixture item")
            reports.append(
                _scenario_result(
                    scenario,
                    [
                        ("items.create", create_size, create_effect),
                        ("items.get", read_size, read_effect),
                        ("items.update", update_size, update_effect),
                        ("items.delete", delete_size, delete_effect),
                    ],
                )
            )

            scenario = "session_batch"
            batch, size, effect = _execute_capability(
                client,
                project,
                trace,
                scenario,
                "items.batch",
                {"body": [{"id": "i-1", "quantity": 4}]},
                confirmation=True,
            )
            if not isinstance(batch, dict) or batch.get("results", [{}])[0].get("status") != 200:
                raise EvidenceError("session batch did not update the fixture item")
            reports.append(_scenario_result(scenario, [("items.batch", size, effect)]))

            scenario = "session_csv"
            preview, preview_size, preview_effect = _execute_capability(
                client,
                project,
                trace,
                scenario,
                "imports.preview",
                {"upload_path": "valid.csv"},
                confirmation=True,
            )
            if not isinstance(preview, dict) or not isinstance(preview.get("import_id"), str):
                raise EvidenceError("session CSV preview did not return an import ID")
            committed, commit_size, commit_effect = _execute_capability(
                client,
                project,
                trace,
                scenario,
                "imports.commit",
                {"id": preview["import_id"]},
                confirmation=True,
            )
            if not isinstance(committed, dict) or committed.get("committed") is not True:
                raise EvidenceError("session CSV import did not commit")
            invalid, invalid_size, invalid_effect = _execute_capability(
                client,
                project,
                trace,
                scenario,
                "imports.preview",
                {"upload_path": "invalid.csv"},
                confirmation=True,
            )
            if not isinstance(invalid, dict) or not isinstance(invalid.get("import_id"), str):
                raise EvidenceError("invalid CSV preview did not return an import ID")
            errors, errors_size, errors_effect = _execute_capability(
                client,
                project,
                trace,
                scenario,
                "imports.errors",
                {"id": invalid["import_id"], "download_path": "session-errors.csv"},
            )
            if not isinstance(errors, dict) or b"invalid quantity" not in (downloads / "session-errors.csv").read_bytes():
                raise EvidenceError("session CSV error report did not download")
            reports.append(
                _scenario_result(
                    scenario,
                    [
                        ("imports.preview", preview_size, preview_effect),
                        ("imports.commit", commit_size, commit_effect),
                        ("imports.preview", invalid_size, invalid_effect),
                        ("imports.errors", errors_size, errors_effect),
                    ],
                )
            )

            scenario = "session_export"
            exported, size, effect = _execute_capability(
                client,
                project,
                trace,
                scenario,
                "items.export",
                {"download_path": "session-items.csv"},
            )
            if not isinstance(exported, dict) or b"Nails,4" not in (downloads / "session-items.csv").read_bytes():
                raise EvidenceError("session CSV export did not download committed rows")
            reports.append(_scenario_result(scenario, [("items.export", size, effect)]))

        elif site == "hybrid_cli":
            scenario = "hybrid_http"
            project_value, size, effect = _execute_capability(
                client, project, trace, scenario, "projects.get", {"id": "p-1"}
            )
            if not isinstance(project_value, dict) or project_value.get("id") != "p-1":
                raise EvidenceError("hybrid HTTP capability did not return the fixture project")
            reports.append(_scenario_result(scenario, [("projects.get", size, effect)]))

            scenario = "hybrid_cli_inspect"
            inspected, size, effect = _execute_capability(
                client, project, trace, scenario, "project.inspect", {"id": "p-1"}
            )
            if not isinstance(inspected, dict) or inspected.get("id") != "p-1":
                raise EvidenceError("hybrid CLI inspect did not execute through STDIO")
            reports.append(_scenario_result(scenario, [("project.inspect", size, effect)]))

            scenario = "hybrid_cli_render"
            rendered, size, effect = _execute_capability(
                client,
                project,
                trace,
                scenario,
                "report.render",
                {"project": "p-1", "output": str(cli_output / "runtime-report.json")},
                confirmation=True,
            )
            if not isinstance(rendered, dict) or not Path(str(rendered.get("path", ""))).is_file():
                raise EvidenceError("hybrid CLI render did not produce a report")
            reports.append(_scenario_result(scenario, [("report.render", size, effect)]))

            scenario = "hybrid_cli_verify"
            verified, size, effect = _execute_capability(
                client,
                project,
                trace,
                scenario,
                "report.verify",
                {"path": str(cli_output / "runtime-report.json")},
            )
            if not isinstance(verified, dict) or verified.get("valid") is not True:
                raise EvidenceError("hybrid CLI verify did not validate the rendered report")
            reports.append(_scenario_result(scenario, [("report.verify", size, effect)]))
        else:  # pragma: no cover - argparse and SITES keep this unreachable
            raise EvidenceError(f"unknown fixture site {site!r}")
    return reports


def run_site(site: str, base_url: str, work_root: Path) -> dict[str, Any]:
    project = work_root / site / "project"
    generated = work_root / site / "generated"
    site_root = work_root / site
    trace: list[dict[str, Any]] = []
    trace_path = work_root / site / "trace.json"
    try:
        environment = _execution_environment(site, site_root)
        command([sys.executable, str(SCAFFOLD), str(project), base_url], trace)
        approve(project, "scope", "spec.md", trace)
        discovery = [sys.executable, str(DISCOVER), str(project), base_url]
        if site == "hybrid_cli":
            discovery.extend(["--cli-contract", str(FIXTURES / "hybrid_cli" / "cli-contract.json")])
        first = command(discovery, trace, expected=3)
        checkpoint = _checkpoint(first)
        if checkpoint == "auth":
            approve(project, "auth", "auth.json", trace)
        approve(project, "native-floor", "action-graph.json", trace)
        approve(project, "final", "coverage.json", trace)
        command(discovery, trace)
        _configure_fixture_execution_contract(site, project, trace)
        command([sys.executable, str(VALIDATE), str(project), "--level", "build"], trace)
        promotions = _record_and_promote(site, project, base_url, trace, environment)
        command([sys.executable, str(VALIDATE), str(project), "--level", "build"], trace, env=environment)
        command([sys.executable, str(GENERATE), str(project), str(generated)], trace, env=environment)
        if not (generated / "skill" / "SKILL.md").is_file():
            raise EvidenceError("generated package omitted its companion skill")
        _capability_trace(generated, trace, environment)
        executions = _execute_promoted_capabilities(site, project, generated, site_root, trace, environment)
        write_json(trace_path, {"site": site, "status": "ok", "events": trace})
        return {
            "site": site,
            "status": "ok",
            "steps": [
                "scaffold",
                "signed_approvals",
                "live_discovery",
                "validate_build",
                "e2e_proof",
                "promote",
                "regenerate",
                "stdio_execute",
            ],
            "trace": str(trace_path),
            "generated_package": str(generated),
            "promotions": promotions,
            "executions": executions,
        }
    except (OSError, subprocess.SubprocessError, EvidenceError, ValueError) as exc:
        trace.append({"kind": "failure", "message": str(exc)})
        write_json(trace_path, {"site": site, "status": "failed", "events": trace})
        return {"site": site, "status": "failed", "error": redact_value(str(exc)), "trace": str(trace_path)}


def run_matrix(output: Path, *, work_root: Path | None = None, sites: tuple[str, ...] = SITES) -> dict[str, Any]:
    if not os.environ.get("WEBSITE_MCP_APPROVAL_KEY"):
        raise EvidenceError("WEBSITE_MCP_APPROVAL_KEY is required for signed fixture approvals")
    output = output.expanduser().resolve()
    work_root = (work_root or output.parent / "fixture-matrix-work").expanduser().resolve()
    if work_root.exists():
        raise EvidenceError(f"work root already exists: {work_root}")
    work_root.mkdir(parents=True)
    fixtures: dict[str, FixtureProcess] = {}
    with ExitStack() as stack:
        for site in sites:
            fixture = FixtureProcess(site).start()
            fixtures[site] = fixture
            stack.callback(fixture.close)
        reports = [run_site(site, fixtures[site].base_url or "", work_root) for site in sites]
    report = {"version": 1, "kind": "fixture_release_matrix", "status": "ok" if all(item["status"] == "ok" for item in reports) else "failed", "sites": reports}
    write_json(output, report)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--work-root", type=Path)
    parser.add_argument("--site", action="append", choices=SITES, dest="sites")
    args = parser.parse_args()
    try:
        report = run_matrix(args.output, work_root=args.work_root, sites=tuple(args.sites or SITES))
    except (OSError, EvidenceError, ValueError) as exc:
        print(redact_value(str(exc)), file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"], "output": str(args.output.expanduser().resolve())}, sort_keys=True))
    return 0 if report["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
