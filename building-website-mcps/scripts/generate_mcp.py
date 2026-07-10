#!/usr/bin/env python3
"""Generate a self-contained stdlib Website MCP from a validated workspace."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any

from validate_workspace import validate


ROOT = Path(__file__).resolve().parents[1]
ASSET = ROOT / "assets" / "python-mcp"


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must be an object")
    return value


def _operations(openapi: dict[str, Any]) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for path, item in openapi.get("paths", {}).items():
        if not isinstance(path, str) or not isinstance(item, dict):
            continue
        path_parameters = item.get("parameters", [])
        for method, operation in item.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete"} or not isinstance(operation, dict):
                continue
            operation_id = operation.get("operationId")
            if not isinstance(operation_id, str):
                continue
            marker = operation.get("x-mcp", {})
            output[operation_id] = {
                "id": operation_id,
                "method": method.upper(),
                "path": path,
                "type": marker.get("type"),
                "parameters": [*path_parameters, *operation.get("parameters", [])],
                "request_body": operation.get("requestBody"),
            }
    return output


def build_config(project: Path) -> dict[str, Any]:
    workspace = project / ".website-mcp"
    state = _load(workspace / "state.json")
    openapi = _load(workspace / "openapi.json")
    graph = _load(workspace / "action-graph.json")
    auth = _load(workspace / "auth.json")
    cli = _load(workspace / "cli.json")
    base_url = state.get("target")
    if not isinstance(base_url, str):
        raise ValueError("state.json must declare the authorized target")
    native_commands = {
        command_id
        for node in graph.get("nodes", [])
        if isinstance(node, dict) and node.get("native") == "yes"
        for command_id in node.get("commands", [])
        if isinstance(command_id, str)
    }
    for command in cli.get("commands", []):
        if not isinstance(command, dict) or command.get("id") not in native_commands:
            continue
        executable = command.get("executable_ref")
        if (
            not isinstance(executable, str)
            or (not executable.startswith("env:") and ("/" in executable or executable.endswith(".py")))
        ):
            raise ValueError("native CLI executable must use an environment reference or PATH command")
    return {
        "version": 1,
        "name": openapi.get("info", {}).get("title", "website-mcp"),
        "base_url": base_url.rstrip("/"),
        "auth": auth,
        "operations": _operations(openapi),
        "capabilities": graph.get("nodes", []),
        "edges": graph.get("edges", []),
        "cli": cli,
        "coverage_gaps": _load(workspace / "coverage.json").get("gaps", []),
        "limits": {"max_limit": 100, "max_download_bytes": 25 * 1024 * 1024, "max_output_bytes": 64 * 1024},
        "io": {"download_root_ref": "env:WEBSITE_MCP_DOWNLOAD_ROOT", "upload_root_ref": "env:WEBSITE_MCP_UPLOAD_ROOT", "cli_root_ref": "env:WEBSITE_MCP_CLI_ROOT"},
    }


def skill_text(config: dict[str, Any]) -> str:
    gaps = config.get("coverage_gaps", [])
    unsupported = [item.get("capability") for item in gaps if isinstance(item, dict)]
    rendered_gaps = ", ".join(str(item) for item in unsupported if item) or "None recorded"
    ids = [item.get("id") for item in config.get("capabilities", []) if isinstance(item, dict) and isinstance(item.get("id"), str)]
    executable_ids = [item.get("id") for item in config.get("capabilities", []) if isinstance(item, dict) and item.get("native") == "yes" and isinstance(item.get("id"), str)]
    example_id = ids[0] if ids else "<search-result-id>"
    execute_id = executable_ids[0] if executable_ids else None
    query = example_id.split(".", 1)[0] if example_id != "<search-result-id>" else "capability"
    execution_example = f'`execute_capability({{"capability_id": "{execute_id}", "arguments": {{}}}})`' if execute_id else "No promoted capability is executable in this artifact. Use search/describe/plan only until a capability is promoted."
    return f'''# Generated Website MCP\n\n## Setup\n\nRun `python server.py` from this generated directory. Configure only the environment-variable references listed in `runtime-config.json`; never place credential values in this directory or tool calls. Set `WEBSITE_MCP_DOWNLOAD_ROOT`, `WEBSITE_MCP_UPLOAD_ROOT`, and `WEBSITE_MCP_CLI_ROOT` to existing trusted directories. `mcp.json` is a standard `mcpServers` configuration with this installation's absolute server path; regenerate after moving the generated directory.\n\n## MCP transport\n\nThe server speaks newline-delimited JSON-RPC over STDIO and requires protocolVersion 2025-06-18. Initialize before using tools:\n\n`{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2025-06-18"}}}}`\n\n## Discovery\n\nStart compactly:\n\n`search_capabilities({{"query": "{query}"}})`\n\nThen load the exact generated contract:\n\n`describe_capabilities({{"ids": ["{example_id}"]}})`\n\nPlan prerequisites before acting:\n\n`plan_workflow({{"capability_id": "{example_id}"}})`\n\nExecute only a promoted capability. For every write, add `confirmation: true`:\n\n{execution_example}\n\n## Safety\n\nOnly promoted capabilities execute. Follow each capability's confirmation policy, keep writes explicit, use relative paths under the configured IO roots, and never ask the MCP to follow redirects. Results are bounded: search 4 KiB, normal reads 8 KiB, batch results 16 KiB, and tools/list 16 KiB; use the documented cursor and field projection inputs when a result is too large.\n\n## Recovery\n\nRead requests may retry once after configured reauthentication. Writes never automatically retry after authentication failure. Inspect the returned error, refresh the configured secret reference, and retry deliberately.\n\n## Unsupported or deferred coverage\n\n{rendered_gaps}\n'''


def generate(project: Path, output: Path) -> None:
    project = project.expanduser().resolve()
    output = output.expanduser().resolve()
    errors = validate(project, "build")
    if errors:
        raise ValueError("workspace is not build-valid: " + "; ".join(errors))
    if output.exists():
        raise ValueError("output directory already exists")
    config = build_config(project)
    shutil.copytree(ASSET, output)
    (output / "runtime-config.json").write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "mcp.json").write_text(
        json.dumps({"mcpServers": {"website-mcp": {"command": sys.executable, "args": [str((output / "server.py").resolve())]}}}, indent=2) + "\n",
        encoding="utf-8",
    )
    skill = output / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text(skill_text(config), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("project", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        generate(args.project, args.output)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(args.output.expanduser().resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
