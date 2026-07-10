#!/usr/bin/env python3
"""Apply a validated, hash-linked stage transition."""

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scaffold_workspace import STAGES, transition_hash

try:
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - exercised by portable import test
    _fcntl = None
try:
    import msvcrt as _msvcrt
except ImportError:  # pragma: no cover - non-Windows platforms
    _msvcrt = None


DEPENDENCIES = {
    "authorize": [],
    "auth": ["authorize"],
    "discover": ["authorize"],
    "model": ["discover"],
    "specify": ["model"],
    "implement": ["model", "specify"],
    "verify": ["implement"],
    "agent-evaluate": ["verify"],
    "harden": ["verify", "agent-evaluate"],
}
ALLOWED = {
    "pending": {"in_progress"},
    "in_progress": {"blocked", "complete"},
    "blocked": {"in_progress"},
    "complete": {"in_progress"},
}


def _lock_file(handle: Any) -> None:
    if _fcntl is not None:
        _fcntl.flock(handle.fileno(), _fcntl.LOCK_EX)
        return
    if _msvcrt is not None:  # pragma: no cover - Windows
        handle.seek(0)
        if not handle.read(1):
            handle.write("0")
            handle.flush()
        handle.seek(0)
        _msvcrt.locking(handle.fileno(), _msvcrt.LK_LOCK, 1)
        return
    raise RuntimeError("no supported file-lock backend; requires POSIX fcntl or Windows msvcrt")


def _unlock_file(handle: Any) -> None:
    if _fcntl is not None:
        _fcntl.flock(handle.fileno(), _fcntl.LOCK_UN)
    elif _msvcrt is not None:  # pragma: no cover - Windows
        handle.seek(0)
        _msvcrt.locking(handle.fileno(), _msvcrt.LK_UNLCK, 1)


def _write_atomic(path: Path, value: object) -> None:
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _transitive_dependents(stage_id: str) -> set[str]:
    found: set[str] = set()
    pending = [stage_id]
    while pending:
        upstream = pending.pop()
        for candidate, dependencies in DEPENDENCIES.items():
            if upstream in dependencies and candidate not in found:
                found.add(candidate)
                pending.append(candidate)
    return found


def _transition_unlocked(
    project: Path,
    stage_id: str,
    destination: str,
    *,
    evidence: list[str],
    reason: str | None,
    actor: str,
) -> None:
    root = project.resolve() / ".website-mcp"
    if root.is_symlink():
        raise ValueError("workspace path is a symlink")
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"workspace contains a symlink: {path.relative_to(root)}")
    state_path = root / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if not isinstance(state, dict):
        raise ValueError("state.json must be an object")
    history_value = state.get("history")
    if not isinstance(history_value, list) or not history_value:
        raise ValueError("state.history must be a non-empty array")
    if any(not isinstance(event, dict) for event in history_value):
        raise ValueError("state.history members must be objects")
    if any(not isinstance(event.get("evidence", []), list) for event in history_value):
        raise ValueError("state.history member evidence must be an array")
    stages_value = state.get("stages")
    if not isinstance(stages_value, list):
        raise ValueError("state.stages must be an array")
    if (
        len(stages_value) != len(STAGES)
        or any(not isinstance(stage, dict) for stage in stages_value)
        or [stage.get("id") for stage in stages_value] != STAGES
    ):
        raise ValueError("state.stages members must match the ordered stage contract")
    for stage in stages_value:
        if stage.get("status") not in ALLOWED:
            raise ValueError("state stage status is invalid")
        if not isinstance(stage.get("evidence"), list):
            raise ValueError("state stage evidence must be an array")
        if not isinstance(stage.get("blockers"), list):
            raise ValueError("state stage blockers must be an array")
        iteration = stage.get("iteration")
        if isinstance(iteration, bool) or not isinstance(iteration, int) or iteration < 0:
            raise ValueError("state stage iteration must be a non-negative integer")
    delay = os.environ.get("WEBSITE_MCP_TEST_DELAY_AFTER_READ")
    if delay:
        time.sleep(float(delay))
    previous = None
    for index, existing_event in enumerate(history_value):
        if existing_event.get("seq") != index + 1:
            raise ValueError("state history sequence is invalid")
        if existing_event.get("previous_hash") != previous:
            raise ValueError("state history chain is invalid")
        if existing_event.get("hash") != transition_hash(existing_event):
            raise ValueError("state history hash is invalid")
        previous = existing_event.get("hash")
    by_id = {stage.get("id"): stage for stage in stages_value}
    if stage_id not in STAGES or stage_id not in by_id:
        raise ValueError(f"unknown stage: {stage_id}")
    stage = by_id[stage_id]
    source = stage.get("status")
    cascade = destination == "invalidate"
    if cascade:
        if stage_id != "discover":
            raise ValueError("cascade invalidation must target discover")
        if source != "complete":
            raise ValueError("cascade invalidation requires completed discovery")
        if not reason:
            raise ValueError("cascade invalidation requires --reason")
        if not evidence:
            raise ValueError("cascade invalidation requires --evidence")
        active_downstream = [
            candidate
            for candidate in STAGES[STAGES.index("specify") :]
            if by_id[candidate].get("status") != "pending"
        ]
        if active_downstream:
            raise ValueError(
                "cannot invalidate discovery/model while downstream stages are active: "
                + ", ".join(active_downstream)
            )
    elif destination not in ALLOWED.get(source, set()):
        raise ValueError(f"illegal transition: {stage_id} {source}->{destination}")

    if not cascade and destination == "in_progress" and source == "pending":
        incomplete = [dep for dep in DEPENDENCIES[stage_id] if by_id[dep].get("status") != "complete"]
        if incomplete:
            raise ValueError(f"dependencies are incomplete: {', '.join(incomplete)}")
    if not cascade and source in {"blocked", "complete"} and destination == "in_progress" and not reason:
        raise ValueError("resuming or reopening a stage requires --reason")
    if not cascade and source == "complete" and destination == "in_progress":
        active_dependents = sorted(
            dependent
            for dependent in _transitive_dependents(stage_id)
            if by_id[dependent].get("status") != "pending"
        )
        if active_dependents:
            raise ValueError(
                "cannot reopen upstream stage while dependent stages are active: "
                + ", ".join(active_dependents)
            )
    if not cascade and destination == "blocked" and not reason:
        raise ValueError("blocked transition requires --reason with the unblock condition")
    if not cascade and destination == "complete" and not evidence:
        raise ValueError("complete transition requires --evidence")
    if not cascade and stage_id == "discover" and destination == "complete":
        try:
            openapi = json.loads((root / "openapi.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("cannot complete discovery with malformed openapi.json") from exc
        paths = openapi.get("paths", {})
        if not isinstance(paths, dict):
            raise ValueError("cannot complete discovery: openapi.paths must be an object")
        root_security = openapi.get("security", [])
        protected = False
        for path_item in paths.values():
            if not isinstance(path_item, dict):
                continue
            for method, operation in path_item.items():
                if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options", "trace"}:
                    continue
                if not isinstance(operation, dict):
                    raise ValueError("cannot complete discovery: OpenAPI operation must be an object")
                effective_security = operation["security"] if "security" in operation else root_security
                if effective_security:
                    protected = True
        if protected and by_id["auth"].get("status") != "complete":
            raise ValueError("cannot complete protected discovery until auth is complete")

    evidence_document = json.loads((root / "evidence-index.json").read_text(encoding="utf-8"))
    if not isinstance(evidence_document, dict) or not isinstance(evidence_document.get("records"), list):
        raise ValueError("evidence-index.records must be an array")
    evidence_records = {
        record.get("id"): record
        for record in evidence_document["records"]
        if isinstance(record, dict)
    }
    known_evidence = set(evidence_records)
    unknown = sorted(set(evidence) - known_evidence)
    if unknown:
        raise ValueError(f"unknown evidence IDs: {', '.join(unknown)}")
    for evidence_id in evidence:
        record = evidence_records[evidence_id]
        artifact_name = record.get("artifact")
        if not isinstance(artifact_name, str):
            raise ValueError(f"evidence artifact is missing: {evidence_id}")
        artifact = root / artifact_name
        try:
            resolved = artifact.resolve(strict=True)
            resolved.relative_to(root.resolve())
        except (OSError, ValueError) as exc:
            raise ValueError(f"evidence artifact is unsafe: {evidence_id}") from exc
        if artifact.is_symlink() or not resolved.is_file():
            raise ValueError(f"evidence artifact is unsafe: {evidence_id}")
        actual = hashlib.sha256(resolved.read_bytes()).hexdigest()
        if record.get("sha256") != actual:
            raise ValueError(f"evidence hash does not match artifact: {evidence_id}")

    history = state.setdefault("history", [])
    previous_hash = history[-1].get("hash") if history else None
    if cascade:
        affected = [
            candidate
            for candidate in ("discover", "model")
            if by_id[candidate].get("status") == "complete"
        ]
        event = {
            "seq": len(history) + 1,
            "kind": "cascade-invalidate",
            "stage": "discover",
            "affected": affected,
            "from": {candidate: by_id[candidate]["status"] for candidate in affected},
            "to": {candidate: "in_progress" for candidate in affected},
            "at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "actor": actor,
            "evidence": evidence,
            "reason": reason,
            "previous_hash": previous_hash,
        }
        event["hash"] = transition_hash(event)
        history.append(event)
        for candidate in affected:
            by_id[candidate]["status"] = "in_progress"
            by_id[candidate]["blockers"] = []
            by_id[candidate]["iteration"] = int(by_id[candidate].get("iteration", 0)) + 1
        _write_atomic(state_path, state)
        return
    event: dict[str, Any] = {
        "seq": len(history) + 1,
        "stage": stage_id,
        "from": source,
        "to": destination,
        "at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "actor": actor,
        "evidence": evidence,
        "reason": reason,
        "previous_hash": previous_hash,
    }
    event["hash"] = transition_hash(event)
    history.append(event)

    stage["status"] = destination
    if destination == "complete":
        stage["evidence"] = list(dict.fromkeys([*stage.get("evidence", []), *evidence]))
        stage["blockers"] = []
    elif destination == "blocked":
        stage["blockers"] = [reason]
    elif destination == "in_progress":
        stage["blockers"] = []
        if source in {"pending", "complete"}:
            stage["iteration"] = int(stage.get("iteration", 0)) + 1
    _write_atomic(state_path, state)


def transition(
    project: Path,
    stage_id: str,
    destination: str,
    *,
    evidence: list[str],
    reason: str | None,
    actor: str,
) -> None:
    project_path = project.expanduser().absolute()
    workspace = project_path / ".website-mcp"
    if workspace.is_symlink():
        raise ValueError("workspace path is a symlink")
    project_path.mkdir(parents=True, exist_ok=True)
    lock_path = project_path / ".website-mcp.lock"
    if lock_path.is_symlink():
        raise ValueError("workspace lock path is a symlink")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    with os.fdopen(descriptor, "a+", encoding="utf-8") as lock:
        _lock_file(lock)
        try:
            _transition_unlocked(
                project_path,
                stage_id,
                destination,
                evidence=evidence,
                reason=reason,
                actor=actor,
            )
        finally:
            _unlock_file(lock)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("project", type=Path)
    parser.add_argument("stage", choices=STAGES)
    parser.add_argument("status", choices=["in_progress", "blocked", "complete", "invalidate"])
    parser.add_argument("--evidence", nargs="+", default=[])
    parser.add_argument("--reason")
    parser.add_argument("--actor", default="lead")
    args = parser.parse_args()
    try:
        transition(
            args.project,
            args.stage,
            args.status,
            evidence=args.evidence,
            reason=args.reason,
            actor=args.actor,
        )
    except (OSError, json.JSONDecodeError, ValueError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
