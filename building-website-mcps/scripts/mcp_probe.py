#!/usr/bin/env python3
"""Small clean-process smoke probe for a generated Website MCP directory."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


def request(process: subprocess.Popen[str], identifier: int, method: str, params: dict[str, Any]) -> dict[str, Any]:
    if process.stdin is None or process.stdout is None:
        raise RuntimeError("probe pipes are unavailable")
    process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": identifier, "method": method, "params": params}) + "\n")
    process.stdin.flush()
    line = process.stdout.readline()
    if not line:
        raise RuntimeError("server closed stdout during probe")
    response = json.loads(line)
    if "error" in response:
        raise RuntimeError(f"rpc_error_{response['error'].get('code')}")
    return response


def probe(directory: Path) -> dict[str, Any]:
    directory = directory.expanduser().resolve()
    server_path = directory / "server.py"
    if not server_path.is_file():
        raise ValueError("generated server.py is missing")
    process = subprocess.Popen(
        [sys.executable, str(server_path)],
        cwd=directory,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        initialized = request(process, 1, "initialize", {"protocolVersion": "2025-06-18"})
        listed = request(process, 2, "tools/list", {})
        request(process, 3, "ping", {})
        tools = listed.get("result", {}).get("tools", [])
        if initialized.get("result", {}).get("protocolVersion") != "2025-06-18" or not isinstance(tools, list):
            raise RuntimeError("probe_response_is_invalid")
        return {"status": "ok", "tools": [item.get("name") for item in tools if isinstance(item, dict)]}
    finally:
        if process.stdin:
            process.stdin.close()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        for stream in (process.stdout, process.stderr):
            if stream:
                stream.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(probe(args.directory), sort_keys=True))
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
