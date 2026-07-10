#!/usr/bin/env python3
"""Safely create or repair the durable website-MCP workspace."""

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


STAGES = [
    "authorize",
    "auth",
    "discover",
    "model",
    "specify",
    "implement",
    "verify",
    "agent-evaluate",
    "harden",
]


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def transition_hash(event: dict[str, Any]) -> str:
    payload = {key: value for key, value in event.items() if key != "hash"}
    return hashlib.sha256(canonical(payload)).hexdigest()


def target_kind(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme in {"http", "https"}:
        if not parsed.hostname or parsed.username is not None or parsed.password is not None:
            raise ValueError("target must be a credential-free HTTP(S) URL")
        return "http"
    if parsed.scheme == "cli":
        if (
            parsed.netloc != "local"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.params
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("target must be the credential-free CLI target cli://local")
        return "cli"
    raise ValueError("target must be a credential-free HTTP(S) URL or cli://local")


def templates(target: str) -> dict[str, str]:
    kind = target_kind(target)
    event: dict[str, Any] = {
        "seq": 1,
        "stage": "authorize",
        "from": "pending",
        "to": "in_progress",
        "at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "actor": "scaffold",
        "evidence": [],
        "reason": "workspace initialized",
        "previous_hash": None,
    }
    event["hash"] = transition_hash(event)
    state = {
        "version": 2,
        "target": target,
        "stages": [
            {
                "id": stage,
                "status": "in_progress" if index == 0 else "pending",
                "evidence": [],
                "blockers": [],
                "iteration": 1 if index == 0 else 0,
            }
            for index, stage in enumerate(STAGES)
        ],
        "history": [event],
    }
    values: dict[str, object] = {
        "state.json": state,
        "auth.json": {
            "version": 2,
            "status": "unknown",
            "modes": [],
            "secret_policy": "references-only",
            "evidence": [],
        },
        "openapi.json": {
            "openapi": "3.1.0",
            "info": {
                "title": "Discovered local CLI capabilities" if kind == "cli" else "Discovered external routes",
                "version": "0.0.0",
            },
            "servers": [] if kind == "cli" else [{"url": target}],
            "paths": {},
        },
        "action-graph.json": {"version": 2, "nodes": [], "edges": []},
        "cli.json": {"version": 2, "commands": []},
        "evidence-index.json": {"version": 2, "records": []},
        "coverage.json": {
            "version": 2,
            "route_counts": {"observed": 0, "modeled": 0, "verified": 0},
            "action_counts": {"observed": 0, "native": 0, "verified": 0},
            "gaps": [],
        },
    }
    rendered = {
        name: json.dumps(value, indent=2) + "\n" for name, value in values.items()
    }
    rendered["spec.md"] = (
        "# Website MCP specification\n\n"
        f"## Authorized scope\n\n- Target: {target}\n- Allowed accounts/data:\n- Forbidden actions:\n\n"
        "## Success tasks\n\n- [ ] Define representative agent task and budget.\n\n"
        "## Performance budgets\n\n- Discovery tokens:\n- Calls per task:\n- p95 latency:\n- Maximum envelope bytes:\n"
    )
    rendered["decisions.md"] = (
        "# Decisions\n\nRecord dated decisions, evidence, confidence, and reversals.\n"
    )
    rendered["discovery-iterations.jsonl"] = ""
    rendered["checkpoints.jsonl"] = ""
    return rendered


def _write_atomic(path: Path, content: str) -> None:
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _assert_no_symlinks(root: Path, names: set[str]) -> None:
    if root.is_symlink():
        raise ValueError("workspace path is a symlink")
    if root.is_dir():
        for path in root.rglob("*"):
            if path.is_symlink():
                raise ValueError(f"workspace contains a symlink: {path.relative_to(root)}")
    for name in names:
        path = root / name
        if path.is_symlink():
            raise ValueError(f"managed path is a symlink: {name}")


def _existing_target(root: Path) -> str:
    path = root / "state.json"
    if not path.is_file():
        raise ValueError("state.json is missing; repair requires a valid resumable state")
    try:
        target = json.loads(path.read_text(encoding="utf-8")).get("target")
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("state.json is malformed; refusing repair") from exc
    if not isinstance(target, str) or not target:
        raise ValueError("state.json target is missing; refusing repair")
    return target


def _assert_consistent_target(root: Path, target: str) -> None:
    existing_target = _existing_target(root)
    if existing_target != target:
        raise ValueError("target mismatch; use --force to replace the workspace")
    openapi_path = root / "openapi.json"
    if not openapi_path.is_file():
        return
    try:
        servers = json.loads(openapi_path.read_text(encoding="utf-8")).get("servers", [])
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("openapi.json is malformed; refusing repair") from exc
    urls = [server.get("url") for server in servers if isinstance(server, dict)]
    if urls and target not in urls:
        raise ValueError("openapi target is inconsistent with state.json")


def _tree_manifest(root: Path) -> dict[str, str]:
    manifest: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        if path.is_symlink():
            manifest[relative] = "symlink:" + os.readlink(path)
        elif path.is_file():
            manifest[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return manifest


def _backup(project: Path, root: Path) -> Path:
    source_manifest = _tree_manifest(root)
    digest = hashlib.sha256(canonical(source_manifest)).hexdigest()[:12]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup_root = project / ".website-mcp.backups"
    if backup_root.is_symlink():
        raise ValueError("backup directory is a symlink")
    backup = backup_root / f"{stamp}-{digest}"
    backup.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(root, backup, symlinks=True)
    if _tree_manifest(backup) != source_manifest:
        shutil.rmtree(backup, ignore_errors=True)
        raise RuntimeError("backup verification failed")
    manifest_path = backup / "backup-manifest.json"
    manifest_path.write_text(
        json.dumps({"source": str(root), "files": source_manifest}, indent=2) + "\n",
        encoding="utf-8",
    )
    return backup


def _build_directory(parent: Path, target: str) -> Path:
    temporary = Path(tempfile.mkdtemp(prefix=".website-mcp.new.", dir=parent))
    try:
        for name, content in templates(target).items():
            (temporary / name).write_text(content, encoding="utf-8")
        return temporary
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def scaffold(project: Path, target: str, *, repair: bool = False, force: bool = False) -> Path:
    target_kind(target)
    project = project.resolve()
    project.mkdir(parents=True, exist_ok=True)
    root = project / ".website-mcp"
    managed = templates(target)
    if repair and force:
        raise ValueError("--repair and --force are mutually exclusive")

    if root.exists() or root.is_symlink():
        if not force and not repair:
            raise FileExistsError(".website-mcp already exists; resume it or use --repair/--force")
        if not force:
            _assert_no_symlinks(root, set(managed))
            _assert_consistent_target(root, target)
            for name, content in managed.items():
                path = root / name
                if not path.exists():
                    _write_atomic(path, content)
            return root

        if root.is_symlink():
            raise ValueError("workspace path is a symlink; refusing destructive replacement")
        _assert_no_symlinks(root, set())
        _backup(project, root)
        fresh = _build_directory(project, target)
        old = project / f".website-mcp.old.{os.getpid()}"
        os.replace(root, old)
        try:
            os.replace(fresh, root)
        except BaseException:
            os.replace(old, root)
            shutil.rmtree(fresh, ignore_errors=True)
            raise
        shutil.rmtree(old)
        return root

    if repair:
        root.mkdir()
        for name, content in managed.items():
            _write_atomic(root / name, content)
        return root

    fresh = _build_directory(project, target)
    try:
        os.replace(fresh, root)
    except BaseException:
        shutil.rmtree(fresh, ignore_errors=True)
        raise
    return root


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("project", type=Path)
    parser.add_argument("target")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--repair", action="store_true")
    mode.add_argument("--force", action="store_true")
    args = parser.parse_args()
    try:
        print(scaffold(args.project, args.target, repair=args.repair, force=args.force))
    except (FileExistsError, ValueError, RuntimeError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
