from __future__ import annotations

from pathlib import Path
from typing import Any

import json
import os
import hashlib
import hmac

from .common import (
    append_jsonl_sequenced_with_context,
    append_jsonl_sequenced_with_context_many,
    canonical,
    ensure_workspace_safe,
    now,
    read_jsonl,
    safe_workspace_artifact,
    sha256_bytes,
)


CHECKPOINTS = {"scope", "auth", "native-floor", "final", "live-write"}
CHECKPOINT_ARTIFACTS = {
    "scope": "spec.md",
    "auth": "auth.json",
    "native-floor": "action-graph.json",
    "final": "coverage.json",
    "live-write": "spec.md",
}
FIXTURE_APPROVER = "fixture-test"
FIXTURE_ACTOR_SOURCE = "fixture-loopback"
COMPILER_ACTOR_SOURCE = "discovery-compiler"
APPROVAL_KEY_ENV = "WEBSITE_MCP_APPROVAL_KEY"


def local_actor() -> str:
    return f"local-uid:{os.getuid()}"


def _trusted_actor_source(actor: str, fixture_test: bool) -> str | None:
    if fixture_test:
        return FIXTURE_ACTOR_SOURCE if actor == FIXTURE_APPROVER else None
    return f"os-uid:{os.getuid()}" if actor == local_actor() else None


def checkpoint_hash(record: dict[str, Any]) -> str:
    payload = {key: value for key, value in record.items() if key not in {"hash", "signature"}}
    return sha256_bytes(canonical(payload))


def _approval_key() -> bytes:
    value = os.environ.get(APPROVAL_KEY_ENV)
    if not value:
        raise ValueError(f"{APPROVAL_KEY_ENV} is required for checkpoint approvals")
    return value.encode("utf-8")


def checkpoint_signature(record: dict[str, Any], key: bytes) -> str:
    payload = {field: value for field, value in record.items() if field != "signature"}
    return hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()


def _validate_ledger(records: list[dict[str, Any]], key: bytes) -> bool:
    previous: str | None = None
    for sequence, record in enumerate(records, 1):
        if not isinstance(record, dict):
            return False
        if record.get("seq") != sequence or record.get("previous_hash") != previous:
            return False
        if record.get("hash") != checkpoint_hash(record):
            return False
        signature = record.get("signature")
        if not isinstance(signature, str) or not hmac.compare_digest(
            signature, checkpoint_signature(record, key)
        ):
            return False
        checkpoint = record.get("checkpoint")
        decision = record.get("decision")
        if checkpoint not in CHECKPOINTS or decision not in {"approve", "reject", "invalidated"}:
            return False
        fixture_test = record.get("fixture_test")
        if not isinstance(fixture_test, bool):
            return False
        if decision == "invalidated":
            if (
                record.get("actor") != "discovery-compiler"
                or record.get("actor_source") != COMPILER_ACTOR_SOURCE
                or fixture_test
                or record.get("artifact") is not None
                or record.get("artifact_sha256") is not None
            ):
                return False
        else:
            artifact = record.get("artifact")
            if artifact != CHECKPOINT_ARTIFACTS.get(checkpoint):
                return False
            source = _trusted_actor_source(str(record.get("actor", "")), fixture_test)
            if source is None or record.get("actor_source") != source:
                return False
        previous = record["hash"]
    return True


def _is_semantically_valid_artifact(workspace: Path, checkpoint: str, artifact: str) -> bool:
    target = safe_workspace_artifact(workspace, artifact)
    if checkpoint in {"scope", "live-write"}:
        text = target.read_text(encoding="utf-8")
        return "## Authorized scope" in text and "Target:" in text
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return False
    if not isinstance(document, dict):
        return False
    required = {
        "auth": ("secret_policy", "modes"),
        "native-floor": ("nodes", "edges"),
        "final": ("route_counts", "action_counts", "gaps"),
    }
    return all(field in document for field in required.get(checkpoint, ()))


def record_checkpoint(
    workspace: Path,
    checkpoint: str,
    decision: str,
    artifact: str,
    actor: str,
    *,
    fixture_test: bool,
    reason: str | None = None,
) -> dict[str, Any]:
    ensure_workspace_safe(workspace)
    key = _approval_key()
    if checkpoint not in CHECKPOINTS:
        raise ValueError(f"unknown checkpoint: {checkpoint}")
    if decision not in {"approve", "reject"}:
        raise ValueError("decision must be approve or reject")
    if not actor.strip():
        raise ValueError("checkpoint actor is required")
    if artifact != CHECKPOINT_ARTIFACTS[checkpoint]:
        raise ValueError(f"checkpoint requires expected artifact: {CHECKPOINT_ARTIFACTS[checkpoint]}")
    actor_source = _trusted_actor_source(actor, fixture_test)
    if actor_source is None:
        raise ValueError("checkpoint actor must match the trusted local actor source")
    target = safe_workspace_artifact(workspace, artifact)
    if decision == "approve" and not _is_semantically_valid_artifact(workspace, checkpoint, artifact):
        raise ValueError("checkpoint artifact is not semantically valid")
    return append_jsonl_sequenced_with_context(
        workspace / "checkpoints.jsonl",
        lambda seq, records: _approval_record(
            seq,
            records,
            checkpoint,
            decision,
            artifact,
            actor,
            actor_source,
            fixture_test,
            reason,
            target,
            key,
        ),
    )


def _approval_record(
    seq: int,
    records: list[dict[str, Any]],
    checkpoint: str,
    decision: str,
    artifact: str,
    actor: str,
    actor_source: str,
    fixture_test: bool,
    reason: str | None,
    target: Path,
    key: bytes,
) -> dict[str, Any]:
    if not _validate_ledger(records, key):
        raise ValueError("checkpoint ledger is invalid")
    record = {
            "seq": seq,
            "checkpoint": checkpoint,
            "decision": decision,
            "actor": actor,
            "actor_source": actor_source,
            "at": now(),
            "artifact": artifact,
            "artifact_sha256": sha256_bytes(target.read_bytes()),
            "fixture_test": fixture_test,
            "reason": reason,
            "previous_hash": records[-1]["hash"] if records else None,
        }
    record["hash"] = checkpoint_hash(record)
    record["signature"] = checkpoint_signature(record, key)
    return record


def invalidate(workspace: Path, checkpoint: str, reason: str) -> None:
    invalidate_many(workspace, [checkpoint], reason)


def invalidate_many(workspace: Path, checkpoints: list[str], reason: str) -> None:
    ensure_workspace_safe(workspace)
    key = _approval_key()
    if any(checkpoint not in CHECKPOINTS for checkpoint in checkpoints):
        raise ValueError("unknown checkpoint invalidation")
    pending = list(dict.fromkeys(checkpoints))
    if not pending:
        return
    append_jsonl_sequenced_with_context_many(
        workspace / "checkpoints.jsonl",
        [
            lambda seq, records, checkpoint=checkpoint: _invalidation_record(
                seq, records, checkpoint, reason, key
            )
            for checkpoint in pending
        ],
    )


def _invalidation_record(
    seq: int, records: list[dict[str, Any]], checkpoint: str, reason: str, key: bytes
) -> dict[str, Any]:
    if not _validate_ledger(records, key):
        raise ValueError("checkpoint ledger is invalid")
    record = {
        "seq": seq,
        "checkpoint": checkpoint,
        "decision": "invalidated",
        "actor": "discovery-compiler",
        "actor_source": COMPILER_ACTOR_SOURCE,
        "at": now(),
        "artifact": None,
        "artifact_sha256": None,
        "fixture_test": False,
        "reason": reason,
        "previous_hash": records[-1]["hash"] if records else None,
    }
    record["hash"] = checkpoint_hash(record)
    record["signature"] = checkpoint_signature(record, key)
    return record


def approved(workspace: Path, checkpoint: str) -> bool:
    try:
        ensure_workspace_safe(workspace)
        ledger = read_jsonl(workspace / "checkpoints.jsonl")
        key = _approval_key()
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    if not _validate_ledger(ledger, key):
        return False
    records = [record for record in ledger if record.get("checkpoint") == checkpoint]
    if not records or records[-1].get("decision") != "approve":
        return False
    latest = records[-1]
    artifact = latest.get("artifact")
    if not isinstance(artifact, str):
        return False
    if artifact != CHECKPOINT_ARTIFACTS.get(checkpoint):
        return False
    try:
        target = safe_workspace_artifact(workspace, artifact)
    except (OSError, ValueError):
        return False
    return (
        _is_semantically_valid_artifact(workspace, checkpoint, artifact)
        and latest.get("artifact_sha256") == sha256_bytes(target.read_bytes())
    )
