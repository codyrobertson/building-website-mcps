#!/usr/bin/env python3
"""Record a reproducible, operator-supplied E2E command as promotion evidence.

This runner proves only that an explicit argv command exited successfully.  It
does not infer route semantics, discover bindings, or make a capability native;
the operator declares an exact existing graph binding and runs the promoter
separately after reviewing the result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import sys
import time
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from promote_capabilities import _atomic_json, _load_object, _workspace_lock
from scan_secrets import (
    KNOWN_SECRET_PATTERNS,
    SAFE_ASSIGNMENT,
    SENSITIVE_ASSIGNMENT,
    _identifier_value,
    _scan_json,
)
from site_to_mcp.common import IDENTIFIER_ASSIGNMENT, is_sensitive_key
from validate_workspace import validate


MAX_ARGV_BYTES = 8 * 1024
MAX_ARGV_ITEMS = 128
MAX_OUTPUT_BYTES = 64 * 1024
MAX_COMMAND_FILE_BYTES = 16 * 1024
EVIDENCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
SHELLS = {
    "sh", "bash", "zsh", "dash", "fish", "ksh", "csh", "tcsh",
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
}


def _parse_array_json(raw: str, label: str) -> list[str]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} must be valid JSON") from exc
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{label} must be a JSON array of strings")
    return value


def _argv_from_file(path: Path) -> list[str]:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_COMMAND_FILE_BYTES:
            raise OSError("unsafe command file")
        return _parse_array_json(path.read_text(encoding="utf-8"), "argv file")
    except OSError as exc:
        raise ValueError("argv file must be a bounded regular file") from exc


def _validate_argv(argv: list[str]) -> None:
    if not argv or len(argv) > MAX_ARGV_ITEMS:
        raise ValueError("argv must contain between 1 and 128 items")
    encoded_size = 0
    for item in argv:
        if not item or "\x00" in item:
            raise ValueError("argv values must be non-empty and contain no NUL bytes")
        encoded_size += len(item.encode("utf-8"))
    if encoded_size > MAX_ARGV_BYTES:
        raise ValueError("argv exceeds the 8192-byte policy")
    if Path(argv[0]).name.lower() in SHELLS:
        raise ValueError("shell commands are not allowed; provide a concrete test executable argv")


def _contains_secret_output(raw: bytes) -> bool:
    text = raw.decode("utf-8", errors="replace")
    errors: list[str] = []
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, (dict, list)):
        _scan_json(parsed, ("proof-output",), errors, "proof-output")
    for line in text.splitlines():
        if any(pattern.search(line) for pattern in KNOWN_SECRET_PATTERNS):
            return True
        assignment = SENSITIVE_ASSIGNMENT.match(line)
        if assignment and not SAFE_ASSIGNMENT.fullmatch(assignment.group(2)):
            return True
        for match in IDENTIFIER_ASSIGNMENT.finditer(line):
            if is_sensitive_key(match.group("key")) and _identifier_value(match) not in {"[REDACTED]", "<redacted>"}:
                return True
    return bool(errors)


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    with suppress(ProcessLookupError, PermissionError):
        os.killpg(process.pid, signal.SIGKILL)
    with suppress(subprocess.TimeoutExpired):
        process.wait(timeout=1)


def _run(argv: list[str], cwd: Path, timeout_seconds: int) -> tuple[int, bytes, bytes, float]:
    started = time.monotonic()
    process = subprocess.Popen(
        argv,
        shell=False,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    selector = selectors.DefaultSelector()
    stdout, stderr = bytearray(), bytearray()
    deadline = started + timeout_seconds
    try:
        assert process.stdout is not None and process.stderr is not None
        selector.register(process.stdout, selectors.EVENT_READ, stdout)
        selector.register(process.stderr, selectors.EVENT_READ, stderr)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate(process)
                raise ValueError("E2E proof command timed out")
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fileobj.fileno(), 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                key.data.extend(chunk)
                if len(stdout) + len(stderr) > MAX_OUTPUT_BYTES:
                    _terminate(process)
                    raise ValueError("E2E proof command output exceeds the 65536-byte policy")
        code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        return code, bytes(stdout), bytes(stderr), (time.monotonic() - started) * 1000
    finally:
        selector.close()
        _terminate(process)
        if process.stdout:
            process.stdout.close()
        if process.stderr:
            process.stderr.close()


def _node_for_binding(graph: dict[str, Any], capability_id: str, operations: list[str], commands: list[str]) -> dict[str, Any]:
    nodes = graph.get("nodes")
    if not isinstance(nodes, list):
        raise ValueError("action-graph.nodes must be an array")
    matches = [node for node in nodes if isinstance(node, dict) and node.get("id") == capability_id]
    if len(matches) != 1 or matches[0].get("native") != "candidate":
        raise ValueError("capability must resolve to exactly one native=candidate node")
    node = matches[0]
    actual_operations = node.get("operations")
    actual_commands = node.get("commands", [])
    if actual_operations != operations or actual_commands != commands:
        raise ValueError("declared binding does not exactly match the candidate operations/commands")
    if not operations and not commands:
        raise ValueError("declared binding has no executable operation or command")
    return node


def record(
    project: Path,
    capability_id: str,
    evidence_id: str,
    operations: list[str],
    commands: list[str],
    argv: list[str],
    timeout_seconds: int,
    fresh_for_seconds: int,
) -> dict[str, Any]:
    if not EVIDENCE_ID.fullmatch(evidence_id):
        raise ValueError("evidence ID must be 1-96 safe filename characters")
    if any(not item for item in operations) or any(not item for item in commands):
        raise ValueError("declared operations and commands must contain non-empty strings")
    _validate_argv(argv)
    project = project.expanduser().resolve()
    workspace = project / ".website-mcp"
    if workspace.is_symlink() or not workspace.is_dir() or any(path.is_symlink() for path in workspace.rglob("*")):
        raise ValueError("workspace path is unsafe")

    with _workspace_lock(project):
        build_errors = validate(project, "build")
        if build_errors:
            raise ValueError("workspace is not build-valid: " + "; ".join(build_errors))
        graph = _load_object(workspace / "action-graph.json")
        _node_for_binding(graph, capability_id, operations, commands)
        index_path = workspace / "evidence-index.json"
        index = _load_object(index_path)
        records = index.get("records")
        if not isinstance(records, list):
            raise ValueError("evidence-index.records must be an array")
        if any(isinstance(record, dict) and record.get("id") == evidence_id for record in records):
            raise ValueError(f"evidence ID already exists: {evidence_id}")
        evidence_dir = workspace / "evidence"
        if evidence_dir.is_symlink():
            raise ValueError("evidence directory is unsafe")
        evidence_dir.mkdir(exist_ok=True)
        artifact = evidence_dir / f"{evidence_id}.json"
        if artifact.exists() or artifact.is_symlink():
            raise ValueError("evidence artifact already exists or is unsafe")

        code, stdout, stderr, duration_ms = _run(argv, project, timeout_seconds)
        if code != 0:
            raise ValueError(f"E2E proof command exited with status {code}")
        if _contains_secret_output(stdout) or _contains_secret_output(stderr):
            raise ValueError("E2E proof command emitted secret-bearing output")

        captured = datetime.now(timezone.utc)
        artifact_value = {
            "version": 1,
            "kind": "operator-command-execution",
            "captured_at": captured.isoformat().replace("+00:00", "Z"),
            "argv_sha256": hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode("utf-8")).hexdigest(),
            "exit_code": code,
            "duration_ms": round(duration_ms, 3),
            "stdout": {"bytes": len(stdout), "sha256": hashlib.sha256(stdout).hexdigest(), "redacted": True},
            "stderr": {"bytes": len(stderr), "sha256": hashlib.sha256(stderr).hexdigest(), "redacted": True},
        }
        _atomic_json(artifact, artifact_value)
        record = {
            "id": evidence_id,
            "kind": "e2e",
            "source": "operator-supplied explicit argv E2E command",
            "captured_at": artifact_value["captured_at"],
            "fresh_until": (captured + timedelta(seconds=fresh_for_seconds)).isoformat().replace("+00:00", "Z"),
            "scope": "capability-promotion",
            "redactions": ["argv", "stdout", "stderr"],
            "redaction_verified": True,
            "artifact": str(artifact.relative_to(workspace)),
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "promotion": {
                "bindings": [{"capability_id": capability_id, "operations": operations, "commands": commands}]
            },
        }
        original_index = index_path.read_bytes()
        records.append(record)
        _atomic_json(index_path, index)
        validation_errors = validate(project, "build")
        if validation_errors:
            index_path.write_bytes(original_index)
            artifact.unlink(missing_ok=True)
            raise ValueError("recorded proof would violate workspace contract: " + "; ".join(validation_errors))
    return {"status": "recorded", "evidence_id": evidence_id, "capability_id": capability_id}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", type=Path)
    parser.add_argument("capability_id")
    parser.add_argument("--evidence-id", required=True)
    parser.add_argument("--operations-json", required=True)
    parser.add_argument("--commands-json", required=True)
    command_source = parser.add_mutually_exclusive_group(required=True)
    command_source.add_argument("--argv-json")
    command_source.add_argument("--argv-file", type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=60)
    parser.add_argument("--fresh-for-seconds", type=int, default=3600)
    args = parser.parse_args()
    try:
        if not 1 <= args.timeout_seconds <= 300:
            raise ValueError("timeout-seconds must be between 1 and 300")
        if not 60 <= args.fresh_for_seconds <= 86_400:
            raise ValueError("fresh-for-seconds must be between 60 and 86400")
        argv = _parse_array_json(args.argv_json, "argv") if args.argv_json is not None else _argv_from_file(args.argv_file)
        result = record(
            args.project,
            args.capability_id,
            args.evidence_id,
            _parse_array_json(args.operations_json, "operations"),
            _parse_array_json(args.commands_json, "commands"),
            argv,
            args.timeout_seconds,
            args.fresh_for_seconds,
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
