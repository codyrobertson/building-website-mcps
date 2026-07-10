#!/usr/bin/env python3
"""Promote one evidence-proven Website MCP capability under a workspace lock.

Discovery records describe possibilities.  This command is the only supported
path from ``native: candidate`` to ``native: yes`` and accepts only current,
hash-valid E2E or contract evidence that names the exact HTTP/CLI bindings.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from validate_workspace import (
    PROMOTION_BINDING_REQUIRED,
    PROMOTION_EVIDENCE_KINDS,
    _validate_openapi,
    derive_coverage,
    validate,
)

try:  # POSIX (the normal Website-MCP build environment)
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - Windows fallback
    _fcntl = None
try:  # pragma: no cover - Windows fallback
    import msvcrt as _msvcrt
except ImportError:  # POSIX
    _msvcrt = None


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path.name} is malformed") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must be an object")
    return value


def _atomic_json(path: Path, value: object) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _lock(handle: Any) -> None:
    if _fcntl is not None:
        _fcntl.flock(handle.fileno(), _fcntl.LOCK_EX)
        return
    if _msvcrt is not None:  # pragma: no cover - Windows fallback
        handle.seek(0)
        if not handle.read(1):
            handle.write("0")
            handle.flush()
        handle.seek(0)
        _msvcrt.locking(handle.fileno(), _msvcrt.LK_LOCK, 1)
        return
    raise RuntimeError("no supported workspace lock backend")


def _unlock(handle: Any) -> None:
    if _fcntl is not None:
        _fcntl.flock(handle.fileno(), _fcntl.LOCK_UN)
    elif _msvcrt is not None:  # pragma: no cover - Windows fallback
        handle.seek(0)
        _msvcrt.locking(handle.fileno(), _msvcrt.LK_UNLCK, 1)


@contextmanager
def _workspace_lock(project: Path) -> Iterator[None]:
    """Use a project-adjacent lock so it never becomes evidence input."""
    lock_path = project / ".website-mcp.promotion.lock"
    handle = lock_path.open("a+", encoding="utf-8")
    try:
        _lock(handle)
        yield
    finally:
        _unlock(handle)
        handle.close()


def _safe_artifact(workspace: Path, record: dict[str, Any], evidence_id: str) -> Path:
    artifact_name = record.get("artifact")
    if not isinstance(artifact_name, str) or not artifact_name:
        raise ValueError(f"promotion evidence artifact is missing: {evidence_id}")
    artifact = workspace / artifact_name
    try:
        resolved = artifact.resolve(strict=True)
        resolved.relative_to(workspace.resolve())
    except (OSError, ValueError) as exc:
        raise ValueError(f"promotion evidence artifact is unsafe: {evidence_id}") from exc
    if artifact.is_symlink() or not resolved.is_file():
        raise ValueError(f"promotion evidence artifact is unsafe: {evidence_id}")
    return resolved


def _require_fresh_hash(record: dict[str, Any], workspace: Path, evidence_id: str) -> None:
    artifact = _safe_artifact(workspace, record, evidence_id)
    digest = record.get("sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError(f"promotion evidence hash is invalid: {evidence_id}")
    if hashlib.sha256(artifact.read_bytes()).hexdigest() != digest:
        raise ValueError(f"promotion evidence hash does not match artifact: {evidence_id}")
    fresh_until = record.get("fresh_until")
    try:
        expiry = datetime.fromisoformat(str(fresh_until).replace("Z", "+00:00"))
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError(f"promotion evidence fresh_until is invalid: {evidence_id}") from exc
    if expiry <= datetime.now(timezone.utc):
        raise ValueError(f"promotion evidence is stale: {evidence_id}")


def _require_exact_binding(
    record: dict[str, Any],
    node: dict[str, Any],
    evidence_id: str,
) -> None:
    if record.get("kind") not in PROMOTION_EVIDENCE_KINDS:
        raise ValueError("promotion evidence kind must be e2e or contract")
    promotion = record.get("promotion")
    bindings = promotion.get("bindings") if isinstance(promotion, dict) else None
    if not isinstance(bindings, list):
        raise ValueError(f"promotion evidence lacks exact bindings: {evidence_id}")
    capability_id = node.get("id")
    operations = node.get("operations")
    commands = node.get("commands")
    for binding in bindings:
        if not isinstance(binding, dict) or PROMOTION_BINDING_REQUIRED - set(binding):
            continue
        if (
            binding.get("capability_id") == capability_id
            and binding.get("operations") == operations
            and binding.get("commands") == commands
        ):
            return
    raise ValueError(f"promotion evidence is irrelevant to exact capability binding: {evidence_id}")


def _validate_candidate(node: object, capability_id: str) -> dict[str, Any]:
    if not isinstance(node, dict):
        raise ValueError("action graph contains a malformed node")
    if node.get("id") != capability_id:
        raise ValueError(f"unknown capability: {capability_id}")
    if node.get("native") != "candidate":
        raise ValueError("promotion requires native=candidate")
    if not isinstance(node.get("operations"), list):
        raise ValueError("candidate bindings must be arrays")
    if "commands" not in node:
        node["commands"] = []
    if not isinstance(node.get("commands"), list):
        raise ValueError("candidate bindings must be arrays")
    if not node["operations"] and not node["commands"]:
        raise ValueError("candidate has no executable binding")
    return node


def _validate_candidate_result(project: Path, workspace: Path, graph: dict[str, Any], coverage: dict[str, Any]) -> None:
    """Validate a full temporary workspace before changing the real one."""
    with tempfile.TemporaryDirectory(prefix=".website-mcp-promotion-", dir=project) as temporary:
        candidate_project = Path(temporary) / "project"
        candidate_workspace = candidate_project / ".website-mcp"
        shutil.copytree(workspace, candidate_workspace)
        _atomic_json(candidate_workspace / "action-graph.json", graph)
        _atomic_json(candidate_workspace / "coverage.json", coverage)
        errors = validate(candidate_project, "build")
        if errors:
            raise ValueError("promotion would violate workspace contract: " + "; ".join(errors))


def promote(project: Path, capability_id: str, evidence_ids: list[str]) -> dict[str, Any]:
    project = project.expanduser().resolve()
    workspace = project / ".website-mcp"
    if workspace.is_symlink() or not workspace.is_dir():
        raise ValueError("workspace path is unsafe")
    if any(path.is_symlink() for path in workspace.rglob("*")):
        raise ValueError("workspace contains a symlink")
    if not evidence_ids or len(evidence_ids) != len(set(evidence_ids)):
        raise ValueError("promotion requires distinct evidence IDs")

    with _workspace_lock(project):
        # The existing candidate workspace must already be a coherent build.
        current_errors = validate(project, "build")
        if current_errors:
            raise ValueError("workspace is not build-valid: " + "; ".join(current_errors))
        graph = _load_object(workspace / "action-graph.json")
        coverage = _load_object(workspace / "coverage.json")
        evidence_index = _load_object(workspace / "evidence-index.json")
        openapi = _load_object(workspace / "openapi.json")
        nodes = graph.get("nodes")
        records = evidence_index.get("records")
        if not isinstance(nodes, list) or not isinstance(records, list):
            raise ValueError("workspace promotion documents are malformed")
        matches = [node for node in nodes if isinstance(node, dict) and node.get("id") == capability_id]
        if len(matches) != 1:
            raise ValueError(f"unknown or ambiguous capability: {capability_id}")
        node = _validate_candidate(matches[0], capability_id)
        record_by_id = {
            record.get("id"): record
            for record in records
            if isinstance(record, dict) and isinstance(record.get("id"), str)
        }
        for evidence_id in evidence_ids:
            record = record_by_id.get(evidence_id)
            if record is None:
                raise ValueError(f"unknown promotion evidence: {evidence_id}")
            _require_exact_binding(record, node, evidence_id)
            _require_fresh_hash(record, workspace, evidence_id)

        existing_evidence = node.get("evidence", [])
        if not isinstance(existing_evidence, list):
            raise ValueError("candidate evidence must be an array")
        node["evidence"] = list(dict.fromkeys([*existing_evidence, *evidence_ids]))
        node["native"] = "yes"
        node["confidence"] = "verified"
        gaps = coverage.get("gaps")
        if not isinstance(gaps, list):
            raise ValueError("coverage.gaps must be an array")
        coverage["gaps"] = [
            gap for gap in gaps
            if not (isinstance(gap, dict) and gap.get("capability") == capability_id)
        ]
        operation_ids, operations = _validate_openapi(openapi, set(record_by_id), [])
        if not operation_ids:
            operations = {}
        valid_evidence = set(record_by_id)
        coverage.update(derive_coverage(operations, nodes, valid_evidence))
        _validate_candidate_result(project, workspace, graph, coverage)
        _atomic_json(workspace / "action-graph.json", graph)
        _atomic_json(workspace / "coverage.json", coverage)
    return {
        "status": "promoted",
        "capability_id": capability_id,
        "evidence": evidence_ids,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", type=Path)
    parser.add_argument("capability_id")
    parser.add_argument("--evidence", action="append", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(promote(args.project, args.capability_id, args.evidence), sort_keys=True))
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
