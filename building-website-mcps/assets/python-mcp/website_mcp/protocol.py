"""Newline-delimited JSON-RPC 2.0 MCP transport; stdout is protocol only."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from .catalog import Catalog, tool_definitions
from .executor import Executor


PROTOCOL_VERSION = "2025-06-18"


class MethodNotFound(ValueError):
    pass


def _response(identifier: Any, result: Any = None, error: tuple[int, str] | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {"jsonrpc": "2.0", "id": identifier}
    if error is None:
        body["result"] = result
    else:
        body["error"] = {"code": error[0], "message": error[1]}
    return body


def _tool_result(value: Any, budget: int, *, error: bool = False) -> dict[str, Any]:
    text = json.dumps(value, sort_keys=True, separators=(",", ":"))
    if len(text.encode("utf-8")) > budget:
        raise ValueError(f"response_exceeds_{budget}_bytes")
    return {
        "content": [{"type": "text", "text": text}],
        "isError": error,
    }


class Server:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.catalog = Catalog(config)
        self.executor = Executor(config)
        self.initialized = False

    def handle(self, request: object) -> dict[str, Any] | None:
        if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
            return _response(None, error=(-32600, "Invalid Request"))
        method = request.get("method")
        identifier = request.get("id")
        notification = "id" not in request
        if not isinstance(method, str):
            return None if notification else _response(identifier, error=(-32600, "Invalid Request"))
        params = request.get("params", {})
        if not isinstance(params, dict):
            return None if notification else _response(identifier, error=(-32602, "Invalid params"))
        try:
            result = self._dispatch(method, params)
        except MethodNotFound as exc:
            return None if notification else _response(identifier, error=(-32601, str(exc)))
        except ValueError as exc:
            return None if notification else _response(identifier, error=(-32602, str(exc)))
        except Exception as exc:  # pragma: no cover - defensive transport boundary
            print(f"website-mcp runtime error: {type(exc).__name__}", file=sys.stderr, flush=True)
            return None if notification else _response(identifier, error=(-32603, "Internal error"))
        return None if notification else _response(identifier, result)

    def _dispatch(self, method: str, params: dict[str, Any]) -> Any:
        if method == "initialize":
            requested = params.get("protocolVersion")
            if requested != PROTOCOL_VERSION:
                raise ValueError("unsupported_protocol_version")
            self.initialized = True
            return {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": self.config.get("name", "website-mcp"), "version": "1.0.0"},
            }
        if method == "notifications/initialized":
            self.initialized = True
            return {}
        if method == "ping":
            return {}
        if method == "tools/list":
            tools = tool_definitions()
            if len(json.dumps({"tools": tools}, separators=(",", ":")).encode("utf-8")) > 16 * 1024:
                raise ValueError("tools_list_exceeds_16384_bytes")
            return {"tools": tools}
        if method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments", {})
            if not isinstance(name, str) or not isinstance(arguments, dict):
                raise ValueError("invalid_tool_call")
            return self._call_tool(name, arguments)
        raise MethodNotFound("Method not found")

    def _call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name == "search_capabilities":
            query = arguments.get("query", "")
            if not isinstance(query, str):
                raise ValueError("query_must_be_string")
            return _tool_result({"capabilities": self.catalog.search(query)}, 4 * 1024)
        if name == "describe_capabilities":
            ids = arguments.get("ids")
            if not isinstance(ids, list) or any(not isinstance(item, str) for item in ids):
                raise ValueError("ids_must_be_string_array")
            return _tool_result({"capabilities": self.catalog.describe(ids)}, 8 * 1024)
        if name == "plan_workflow":
            capability_id = arguments.get("capability_id")
            if not isinstance(capability_id, str):
                raise ValueError("capability_id_must_be_string")
            return _tool_result(self.catalog.plan(capability_id), 8 * 1024)
        if name == "execute_capability":
            capability_id = arguments.get("capability_id")
            if not isinstance(capability_id, str):
                raise ValueError("capability_id_must_be_string")
            node = self.catalog.executable(capability_id)
            if node.get("side_effect") not in {"none", "read"} and arguments.get("confirmation") is not True:
                raise ValueError("confirmation_required")
            budget = 16 * 1024 if node.get("execution") == "batch" else 8 * 1024
            return _tool_result(self.executor.execute(node, arguments.get("arguments", {})), budget)
        raise ValueError("unknown_tool")


def serve(config_path: Path) -> None:
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"website-mcp startup failed: {type(exc).__name__}", file=sys.stderr, flush=True)
        raise SystemExit(2)
    server = Server(config)
    for raw in sys.stdin:
        try:
            request = json.loads(raw)
        except json.JSONDecodeError:
            print(json.dumps(_response(None, error=(-32700, "Parse error")), sort_keys=True), flush=True)
            continue
        response = server.handle(request)
        if response is not None:
            print(json.dumps(response, separators=(",", ":"), sort_keys=True), flush=True)
