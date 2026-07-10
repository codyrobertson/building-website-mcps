#!/usr/bin/env python3
"""Validate the supported OpenAPI 3.1 semantic subset and website-MCP readiness gates.

This is deliberately not a complete OpenAPI 3.1 meta-schema implementation.
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from scaffold_workspace import STAGES, target_kind, transition_hash
from scan_secrets import scan_workspace
from site_to_mcp.common import read_jsonl
from transition_stage import ALLOWED, DEPENDENCIES


REQUIRED = {
    "action-graph.json",
    "auth.json",
    "cli.json",
    "coverage.json",
    "checkpoints.jsonl",
    "decisions.md",
    "discovery-iterations.jsonl",
    "evidence-index.json",
    "openapi.json",
    "spec.md",
    "state.json",
}
METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
TYPES = {"auth", "read", "create", "update", "delete", "action", "upload", "download"}
OPENAPI_SURFACES = {"http", "hybrid"}
GRAPH_SURFACES = {"http", "ui", "hybrid", "stdio"}
AUTH_KINDS = {
    "anonymous",
    "api-key",
    "bearer",
    "oauth",
    "service-account",
    "cookie-session",
    "browser-session",
}
STATUSES = {"pending", "in_progress", "blocked", "complete"}
EXECUTIONS = {"independent", "sequential", "batch", "paginated", "upload-stream", "download-stream"}
NATIVE = {"no", "candidate", "yes", "fallback"}
CONFIDENCE = {"observed", "inferred", "verified"}
SIDE_EFFECTS = {"none", "read", "write", "destructive"}
GAP_DISPOSITIONS = {"open", "accepted", "deferred", "unsupported", "resolved"}
EXECUTABLE_REFERENCE = re.compile(
    r"^(?:env:[A-Z_][A-Z0-9_]*|[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*)$"
)
DYNAMIC_EVIDENCE_KINDS = {
    "auth-proof", "e2e", "contract", "benchmark", "cold-agent", "agent-evaluate", "hardening",
}
TIMELESS_EVIDENCE_KINDS = {
    "test", "authorization", "route-discovery", "model-proof", "specification",
    "implementation", "official-doc", "source-code", "schema", "cli-version",
}
EDGE_KINDS = {"requires", "produces", "consumes", "precedes", "alternative", "contains"}
EVIDENCE_REQUIRED = {
    "id",
    "kind",
    "source",
    "captured_at",
    "scope",
    "redactions",
    "redaction_verified",
    "artifact",
    "sha256",
}
GRAPH_REQUIRED = {
    "id", "intent", "surface", "operations", "native", "execution", "auth",
    "side_effect", "confirmation", "evidence", "confidence",
}
GAP_REQUIRED = {
    "id", "capability", "impact", "evidence", "workaround", "owner", "disposition",
}
PROMOTION_EVIDENCE_KINDS = {"e2e", "contract"}
PROMOTION_BINDING_REQUIRED = {"capability_id", "operations", "commands"}


def load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path.name}: {exc}") from exc


def _is_object(value: object, name: str, errors: list[str]) -> bool:
    if not isinstance(value, dict):
        errors.append(f"{name} must be an object")
        return False
    return True


def _check_evidence_refs(
    value: object, label: str, known: set[str], errors: list[str]
) -> None:
    if not isinstance(value, list):
        errors.append(f"{label} must be an array of evidence IDs")
        return
    for evidence_id in value:
        if not isinstance(evidence_id, str) or evidence_id not in known:
            errors.append(f"{label} references unknown evidence: {evidence_id}")


def _resolve_pointer(document: object, reference: str) -> bool:
    if reference == "#":
        return True
    if not reference.startswith("#/"):
        return False
    current = document
    for raw in reference[2:].split("/"):
        part = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return False
    return True


def _validate_refs(document: object, label: str, errors: list[str]) -> None:
    def walk(value: object, pointer: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                child_pointer = f"{pointer}/{key}"
                if key == "$ref":
                    if not isinstance(child, str) or not child.startswith("#"):
                        errors.append(f"{label}{child_pointer}: unsafe $ref")
                    elif not _resolve_pointer(document, child):
                        errors.append(f"{label}{child_pointer}: dangling $ref")
                else:
                    walk(child, child_pointer)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{pointer}/{index}")

    walk(document, "")


def _valid_evidence(workspace: Path, document: object, errors: list[str]) -> tuple[set[str], set[str]]:
    if not _is_object(document, "evidence-index", errors):
        return set(), set()
    records = document.get("records", [])
    if not isinstance(records, list):
        errors.append("evidence-index.records must be an array")
        return set(), set()
    known: set[str] = set()
    hash_valid: set[str] = set()
    for index, record in enumerate(records):
        prefix = f"evidence-index.records[{index}]"
        if not isinstance(record, dict):
            errors.append(f"{prefix} must be an object")
            continue
        missing = EVIDENCE_REQUIRED - set(record)
        if missing:
            errors.append(f"{prefix} missing {sorted(missing)}")
        evidence_id = record.get("id")
        if not isinstance(evidence_id, str) or not evidence_id.strip():
            errors.append(f"{prefix}.id must be a non-empty string")
            continue
        if evidence_id in known:
            errors.append(f"{prefix}.id is duplicated: {evidence_id}")
        known.add(evidence_id)
        if "fresh_until" not in record and record.get("immutable") is not True:
            errors.append(f"{prefix} requires fresh_until or immutable=true")
        if record.get("immutable") is True and record.get("kind") not in TIMELESS_EVIDENCE_KINDS:
            errors.append(f"{prefix} kind={record.get('kind')} cannot be immutable")
        if record.get("kind") in DYNAMIC_EVIDENCE_KINDS and "fresh_until" not in record:
            errors.append(f"{prefix} kind={record.get('kind')} requires fresh_until")
        if record.get("redaction_verified") is not True:
            errors.append(f"{prefix}.redaction_verified must be true")
        artifact_name = record.get("artifact")
        if not isinstance(artifact_name, str) or not artifact_name:
            continue
        artifact = workspace / artifact_name
        try:
            resolved = artifact.resolve(strict=True)
            resolved.relative_to(workspace.resolve())
        except (OSError, ValueError):
            errors.append(f"{prefix}.artifact must resolve inside .website-mcp")
            continue
        if artifact.is_symlink() or not resolved.is_file():
            errors.append(f"{prefix}.artifact must be a regular non-symlink file")
            continue
        expected = record.get("sha256")
        actual = hashlib.sha256(resolved.read_bytes()).hexdigest()
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            errors.append(f"{prefix}.sha256 must be 64 lowercase hex characters")
        elif expected != actual:
            errors.append(f"{prefix}.sha256 does not match artifact")
        else:
            if record.get("immutable") is True:
                hash_valid.add(evidence_id)
            else:
                fresh_until = record.get("fresh_until")
                try:
                    expiry = datetime.fromisoformat(str(fresh_until).replace("Z", "+00:00"))
                    if expiry.tzinfo is None:
                        expiry = expiry.replace(tzinfo=timezone.utc)
                    if expiry <= datetime.now(timezone.utc):
                        errors.append(f"{prefix} is stale")
                    else:
                        hash_valid.add(evidence_id)
                except ValueError:
                    errors.append(f"{prefix}.fresh_until must be an ISO timestamp")
    return known, hash_valid


def _validate_release_proofs(
    state: dict[str, Any],
    auth: object,
    evidence: object,
    current_evidence: set[str],
    errors: list[str],
) -> None:
    if not isinstance(auth, dict) or auth.get("status") not in {"verified", "anonymous"}:
        errors.append("release auth.status must be verified or anonymous")
    record_list_value = evidence.get("records", []) if isinstance(evidence, dict) else []
    record_list = record_list_value if isinstance(record_list_value, list) else []
    records = {
        record.get("id"): record
        for record in record_list
        if isinstance(record, dict) and isinstance(record.get("id"), str)
    }
    stage_list_value = state.get("stages", [])
    stage_list = stage_list_value if isinstance(stage_list_value, list) else []
    stages = {
        stage.get("id"): stage
        for stage in stage_list
        if isinstance(stage, dict)
    }
    requirements = [
        ("authorize", "authorization", "authorized-scope", "authorization"),
        ("auth", "auth-proof", "auth", "auth"),
        ("discover", "route-discovery", "discovery", "discovery"),
        ("model", "model-proof", "model", "model"),
        ("specify", "specification", "specification", "specification"),
        ("implement", "implementation", "implementation", "implementation"),
        ("verify", "e2e", "e2e", "E2E"),
        ("verify", "benchmark", "performance", "benchmark"),
        ("agent-evaluate", "cold-agent", "agent-evaluation", "cold-agent"),
        ("harden", "hardening", "hardening", "hardening"),
    ]
    used: set[str] = set()
    for stage_id, kind, scope, label in requirements:
        stage_evidence_value = stages.get(stage_id, {}).get("evidence", [])
        stage_evidence = stage_evidence_value if isinstance(stage_evidence_value, list) else []
        matches = [
            evidence_id
            for evidence_id in stage_evidence
            if evidence_id in current_evidence
            and records.get(evidence_id, {}).get("kind") == kind
            and records.get(evidence_id, {}).get("scope") == scope
        ]
        if not matches:
            errors.append(
                f"release {label} proof requires fresh evidence kind={kind} scope={scope}"
            )
            continue
        chosen = matches[0]
        if chosen in used:
            errors.append(f"release proof evidence must be distinct: {chosen}")
        used.add(chosen)


def _validate_history(state: dict[str, Any], known_evidence: set[str], errors: list[str]) -> None:
    stages = state.get("stages", [])
    if not isinstance(stages, list):
        errors.append("state.stages must be an array")
        return
    if [stage.get("id") if isinstance(stage, dict) else None for stage in stages] != STAGES:
        errors.append("state.stages must match the full ordered stage contract")
        return
    for index, stage in enumerate(stages):
        if stage.get("status") not in STATUSES:
            errors.append(f"state.stages[{index}].status is invalid")
        evidence = stage.get("evidence", [])
        if stage.get("status") == "complete" and not evidence:
            errors.append(f"state.stages[{index}] complete requires evidence")
        if stage.get("status") == "blocked" and not stage.get("blockers"):
            errors.append(f"state.stages[{index}] blocked requires an unblock condition")
        for evidence_id in evidence if isinstance(evidence, list) else []:
            if evidence_id not in known_evidence:
                errors.append(f"state.stages[{index}] references unknown evidence: {evidence_id}")

    reconstructed = {stage: "pending" for stage in STAGES}
    history = state.get("history", [])
    if not isinstance(history, list) or not history:
        errors.append("state.history must be a non-empty array")
        return
    previous_hash = None
    for index, event in enumerate(history):
        prefix = f"state.history[{index}]"
        if not isinstance(event, dict):
            errors.append(f"{prefix} must be an object")
            continue
        if event.get("seq") != index + 1:
            errors.append(f"{prefix}.seq is invalid")
        if event.get("previous_hash") != previous_hash:
            errors.append(f"{prefix}.previous_hash does not match history chain")
        if event.get("hash") != transition_hash(event):
            errors.append(f"{prefix}.history hash is invalid")
        stage_id = event.get("stage")
        if stage_id not in reconstructed:
            errors.append(f"{prefix}.stage is invalid")
            previous_hash = event.get("hash")
            continue
        if event.get("kind") == "cascade-invalidate":
            affected = event.get("affected")
            source_map = event.get("from")
            destination_map = event.get("to")
            if (
                stage_id != "discover"
                or not isinstance(affected, list)
                or not affected
                or any(candidate not in {"discover", "model"} for candidate in affected)
                or not isinstance(source_map, dict)
                or not isinstance(destination_map, dict)
            ):
                errors.append(f"{prefix} cascade invalidation shape is invalid")
            else:
                if any(reconstructed[candidate] != "complete" for candidate in affected):
                    errors.append(f"{prefix} cascade invalidation requires completed stages")
                if source_map != {candidate: "complete" for candidate in affected}:
                    errors.append(f"{prefix} cascade invalidation source is invalid")
                if destination_map != {candidate: "in_progress" for candidate in affected}:
                    errors.append(f"{prefix} cascade invalidation destination is invalid")
                active_downstream = [
                    candidate
                    for candidate in STAGES[STAGES.index("specify") :]
                    if reconstructed[candidate] != "pending"
                ]
                if active_downstream:
                    errors.append(f"{prefix} cascade invalidation has active downstream stages")
                for candidate in affected:
                    reconstructed[candidate] = "in_progress"
            if not event.get("reason"):
                errors.append(f"{prefix} cascade invalidation requires a reason")
            _check_evidence_refs(
                event.get("evidence", []), f"{prefix}.evidence", known_evidence, errors
            )
            previous_hash = event.get("hash")
            continue
        source, destination = event.get("from"), event.get("to")
        if source != reconstructed[stage_id]:
            errors.append(f"{prefix}.from does not match reconstructed state")
        if destination not in ALLOWED.get(source, set()):
            errors.append(f"{prefix} contains an illegal transition")
        if source == "pending" and destination == "in_progress":
            incomplete = [dep for dep in DEPENDENCIES[stage_id] if reconstructed[dep] != "complete"]
            if incomplete:
                errors.append(f"{prefix} started before dependencies: {', '.join(incomplete)}")
        if destination == "complete" and not event.get("evidence"):
            errors.append(f"{prefix} complete requires evidence")
        _check_evidence_refs(
            event.get("evidence", []), f"{prefix}.evidence", known_evidence, errors
        )
        if destination == "blocked" and not event.get("reason"):
            errors.append(f"{prefix} blocked requires a reason")
        if source in {"blocked", "complete"} and destination == "in_progress" and not event.get("reason"):
            errors.append(f"{prefix} reopen/resume requires a reason")
        if source == "complete" and destination == "in_progress":
            active_dependents = [
                candidate
                for candidate, dependencies in DEPENDENCIES.items()
                if stage_id in dependencies and reconstructed[candidate] != "pending"
            ]
            if active_dependents:
                errors.append(f"{prefix} reopened upstream of active dependent stages")
        reconstructed[stage_id] = destination
        previous_hash = event.get("hash")
    for stage in stages:
        if stage.get("status") != reconstructed.get(stage.get("id")):
            errors.append(f"state stage snapshot does not match history: {stage.get('id')}")


def _validate_openapi(
    openapi: object, known_evidence: set[str], errors: list[str]
) -> tuple[set[str], dict[str, dict[str, Any]]]:
    if not _is_object(openapi, "openapi.json", errors):
        return set(), {}
    if not re.fullmatch(r"3\.1\.\d+", str(openapi.get("openapi", ""))):
        errors.append("openapi.json must use an exact 3.1.x version")
    info = openapi.get("info")
    if not isinstance(info, dict):
        errors.append("openapi.info must be an object")
    else:
        for field in ("title", "version"):
            if not isinstance(info.get(field), str) or not info.get(field, "").strip():
                errors.append(f"openapi.info.{field} must be a non-empty string")
    if "paths" not in openapi:
        errors.append("openapi.paths is required")
    paths = openapi.get("paths", {})
    if not isinstance(paths, dict):
        errors.append("openapi.paths must be an object")
        return set(), {}
    operation_ids: set[str] = set()
    operations: dict[str, dict[str, Any]] = {}
    components = openapi.get("components", {})
    security_schemes = (
        components.get("securitySchemes", {}) if isinstance(components, dict) else {}
    )
    if not isinstance(security_schemes, dict):
        errors.append("openapi.components.securitySchemes must be an object")
        security_schemes = {}

    def validate_security(value: object, prefix: str) -> None:
        if not isinstance(value, list):
            errors.append(f"{prefix} must be an array")
            return
        for index, requirement in enumerate(value):
            if not isinstance(requirement, dict):
                errors.append(f"{prefix}[{index}] must be an object")
                continue
            for scheme, scopes in requirement.items():
                if scheme not in security_schemes:
                    errors.append(f"{prefix}[{index}] references unknown security scheme: {scheme}")
                if not isinstance(scopes, list):
                    errors.append(f"{prefix}[{index}].{scheme} scopes must be an array")

    if "security" in openapi:
        validate_security(openapi.get("security"), "openapi.security")
    for route, path_item in paths.items():
        template_names = re.findall(r"\{([^{}]+)\}", route)
        if (
            not isinstance(route, str)
            or not route.startswith("/")
            or route.count("{") != route.count("}")
            or any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", name) for name in template_names)
        ):
            errors.append(f"paths.{route}: path template is invalid")
        if not isinstance(path_item, dict):
            errors.append(f"paths.{route} must be an object")
            continue
        path_parameters_value = path_item.get("parameters", [])
        path_parameters = path_parameters_value if isinstance(path_parameters_value, list) else []
        if not isinstance(path_parameters_value, list):
            errors.append(f"paths.{route}.parameters must be an array")
        for method, operation in path_item.items():
            if method.lower() not in METHODS:
                continue
            prefix = f"paths.{route}.{method}"
            if not isinstance(operation, dict):
                errors.append(f"{prefix} must be an object")
                continue
            operation_id = operation.get("operationId")
            if not isinstance(operation_id, str) or not operation_id:
                errors.append(f"{prefix}.operationId is required")
            elif operation_id in operation_ids:
                errors.append(f"{prefix}.operationId is duplicated")
            else:
                operation_ids.add(operation_id)
                operations[operation_id] = operation
            if not isinstance(operation.get("responses"), dict) or not operation["responses"]:
                errors.append(f"{prefix}.responses must be a non-empty object")
            else:
                for response_key, response in operation["responses"].items():
                    if not re.fullmatch(r"(?:default|[1-5](?:\d{2}|XX))", str(response_key), re.IGNORECASE):
                        errors.append(f"{prefix}.responses response key is invalid: {response_key}")
                    if not isinstance(response, dict):
                        errors.append(f"{prefix}.responses.{response_key} must be an object")
                    elif "$ref" not in response and (
                        not isinstance(response.get("description"), str)
                        or not response.get("description", "").strip()
                    ):
                        errors.append(
                            f"{prefix}.responses.{response_key} requires description or $ref"
                        )
            operation_parameters_value = operation.get("parameters", [])
            operation_parameters = operation_parameters_value if isinstance(operation_parameters_value, list) else []
            if not isinstance(operation_parameters_value, list):
                errors.append(f"{prefix}.parameters must be an array")
            declared: dict[str, dict[str, Any]] = {}
            for parameter in [*path_parameters, *operation_parameters]:
                if not isinstance(parameter, dict):
                    errors.append(f"{prefix}.parameters members must be objects")
                    continue
                if parameter.get("in") == "path" and isinstance(parameter.get("name"), str):
                    declared[parameter["name"]] = parameter
            for name in template_names:
                parameter = declared.get(name)
                if parameter is None:
                    errors.append(f"{prefix} missing required path parameter declaration: {name}")
                elif parameter.get("required") is not True or not isinstance(parameter.get("schema"), dict):
                    errors.append(f"{prefix} path parameter {name} requires required=true and schema object")
            if "security" in operation:
                validate_security(operation.get("security"), f"{prefix}.security")
            marker = operation.get("x-mcp")
            marker_prefix = f"{prefix}.x-mcp"
            if not isinstance(marker, dict):
                errors.append(f"{marker_prefix} is required")
                continue
            missing = {"route", "type", "surface"} - set(marker)
            if missing:
                errors.append(f"{marker_prefix} missing required keys: {sorted(missing)}")
            if marker.get("route") != route:
                errors.append(f"{marker_prefix}.route must equal its OpenAPI path")
            if marker.get("type") not in TYPES:
                errors.append(f"{marker_prefix}.type is invalid")
            if marker.get("surface") not in OPENAPI_SURFACES:
                errors.append(f"{marker_prefix}.surface is invalid")
            if "evidence" in marker:
                _check_evidence_refs(marker.get("evidence"), f"{marker_prefix}.evidence", known_evidence, errors)
    return operation_ids, operations


def _validate_auth(auth: object, known_evidence: set[str], errors: list[str]) -> set[str]:
    if not _is_object(auth, "auth.json", errors):
        return set()
    if auth.get("secret_policy") != "references-only":
        errors.append("auth.secret_policy must be references-only")
    _check_evidence_refs(auth.get("evidence", []), "auth.evidence", known_evidence, errors)
    ids: set[str] = set()
    modes = auth.get("modes", [])
    if not isinstance(modes, list):
        errors.append("auth.modes must be an array")
        return ids
    for index, mode in enumerate(modes):
        if not isinstance(mode, dict):
            errors.append(f"auth.modes[{index}] must be an object")
            continue
        mode_id = mode.get("id")
        if not isinstance(mode_id, str) or not mode_id:
            errors.append(f"auth.modes[{index}].id must be a non-empty string")
        elif mode_id in ids:
            errors.append(f"auth.modes[{index}].id is duplicated")
        else:
            ids.add(mode_id)
        if mode.get("kind") not in AUTH_KINDS:
            errors.append(f"auth.modes[{index}].kind is an invalid auth kind")
        mode_evidence_value = mode.get("evidence", [])
        mode_evidence = mode_evidence_value if isinstance(mode_evidence_value, list) else []
        if not isinstance(mode_evidence_value, list):
            errors.append(f"auth.modes[{index}].evidence must be an array")
        for evidence_id in mode_evidence:
            if evidence_id not in known_evidence:
                errors.append(f"auth.modes[{index}] references unknown evidence: {evidence_id}")
    return ids


def has_exact_promotion_evidence(
    node: dict[str, Any],
    evidence_records: dict[str, dict[str, Any]],
    valid_evidence: set[str],
) -> bool:
    """Whether one current proof record binds exactly this capability's adapters.

    Discovery evidence is deliberately excluded.  An E2E/contract artifact must
    name the capability and all of its operation/command bindings so a proof for
    a nearby endpoint cannot promote a broader capability by accident.
    """
    node_id = node.get("id")
    operations = node.get("operations")
    commands = node.get("commands", [])
    evidence_ids = node.get("evidence")
    if (
        not isinstance(node_id, str)
        or not isinstance(operations, list)
        or not isinstance(commands, list)
        or not isinstance(evidence_ids, list)
    ):
        return False
    for evidence_id in evidence_ids:
        if not isinstance(evidence_id, str) or evidence_id not in valid_evidence:
            continue
        record = evidence_records.get(evidence_id)
        if not isinstance(record, dict) or record.get("kind") not in PROMOTION_EVIDENCE_KINDS:
            continue
        promotion = record.get("promotion")
        bindings = promotion.get("bindings") if isinstance(promotion, dict) else None
        if not isinstance(bindings, list):
            continue
        for binding in bindings:
            if not isinstance(binding, dict) or PROMOTION_BINDING_REQUIRED - set(binding):
                continue
            if (
                binding.get("capability_id") == node_id
                and binding.get("operations") == operations
                and binding.get("commands") == commands
            ):
                return True
    return False


def _validate_graph(
    graph: object,
    operation_ids: set[str],
    command_ids: set[str],
    auth_ids: set[str],
    evidence_ids: set[str],
    valid_evidence: set[str],
    evidence_records: dict[str, dict[str, Any]],
    level: str,
    errors: list[str],
) -> list[dict[str, Any]]:
    if not _is_object(graph, "action-graph.json", errors):
        return []
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    if not isinstance(nodes, list):
        errors.append("action-graph.nodes must be an array")
        return []
    if not isinstance(edges, list):
        errors.append("action-graph.edges must be an array")
        edges = []
    node_ids: set[str] = set()
    valid_nodes: list[dict[str, Any]] = []
    for index, node in enumerate(nodes):
        prefix = f"action-graph.nodes[{index}]"
        if not isinstance(node, dict):
            errors.append(f"{prefix} must be an object")
            continue
        valid_nodes.append(node)
        if level in {"build", "release"}:
            missing_fields = GRAPH_REQUIRED - set(node)
            if missing_fields:
                errors.append(f"{prefix} missing required fields: {sorted(missing_fields)}")
        node_id = node.get("id")
        if not isinstance(node_id, str) or not node_id.strip():
            errors.append(f"{prefix}.id must be a non-empty string")
        elif node_id in node_ids:
            errors.append(f"{prefix}.id is duplicated")
        else:
            node_ids.add(node_id)
        if "surface" in node and node.get("surface") not in GRAPH_SURFACES:
            errors.append(f"{prefix}.surface is invalid")
        if "execution" in node and node.get("execution") not in EXECUTIONS:
            errors.append(f"{prefix}.execution is invalid")
        if "native" in node and node.get("native") not in NATIVE:
            errors.append(f"{prefix}.native is invalid")
        if level in {"build", "release"} and (
            not isinstance(node.get("intent"), str) or not node.get("intent", "").strip()
        ):
            errors.append(f"{prefix}.intent must be a non-empty string")
        operations_value = node.get("operations", [])
        operations = operations_value if isinstance(operations_value, list) else []
        if not isinstance(operations_value, list):
            errors.append(f"{prefix}.operations must be an array")
        commands_value = node.get("commands", [])
        commands = commands_value if isinstance(commands_value, list) else []
        if not isinstance(commands_value, list):
            errors.append(f"{prefix}.commands must be an array")
        auth_value = node.get("auth", [])
        auth_refs = auth_value if isinstance(auth_value, list) else []
        if not isinstance(auth_value, list):
            errors.append(f"{prefix}.auth must be an array")
        evidence_value = node.get("evidence", [])
        node_evidence_refs = evidence_value if isinstance(evidence_value, list) else []
        if not isinstance(evidence_value, list):
            errors.append(f"{prefix}.evidence must be an array")
        if level in {"build", "release"}:
            if node.get("side_effect") not in SIDE_EFFECTS:
                errors.append(f"{prefix}.side_effect is invalid")
            if not isinstance(node.get("confirmation"), str) or not node.get("confirmation", "").strip():
                errors.append(f"{prefix}.confirmation must be a non-empty string")
            if node.get("confidence") not in CONFIDENCE:
                errors.append(f"{prefix}.confidence is invalid")
            surface = node.get("surface")
            if surface in {"http", "hybrid"} and not operations:
                errors.append(f"{prefix} requires an HTTP operation binding")
            if surface == "stdio" and not commands:
                errors.append(f"{prefix} requires a CLI command binding")
            if surface == "ui" and (
                node.get("native") not in {"no", "fallback"} or not node_evidence_refs
            ):
                errors.append(f"{prefix} UI capability requires an evidenced fallback")
            if not operations and not commands and surface != "ui":
                errors.append(f"{prefix} has no executable HTTP/CLI binding")
        for operation_id in operations:
            if operation_id not in operation_ids:
                errors.append(f"{prefix} references unknown operationId: {operation_id}")
        for command_id in commands:
            if command_id not in command_ids:
                errors.append(f"{prefix} references unknown CLI command: {command_id}")
        for auth_id in auth_refs:
            if auth_id not in auth_ids:
                errors.append(f"{prefix} references unknown auth mode: {auth_id}")
        for evidence_id in node_evidence_refs:
            if evidence_id not in evidence_ids:
                errors.append(f"{prefix} references unknown evidence: {evidence_id}")
        if level in {"build", "release"} and node.get("native") == "yes":
            node_evidence = node_evidence_refs
            if (
                node.get("confidence") != "verified"
                or not node_evidence
                or not isinstance(node_evidence, list)
                or not set(node_evidence) <= valid_evidence
            ):
                errors.append(f"{prefix} native=yes requires verified confidence and valid evidence")
            if not has_exact_promotion_evidence(node, evidence_records, valid_evidence):
                errors.append(
                    f"{prefix} native=yes requires a fresh hash-valid exact e2e or contract promotion evidence"
                )
    for index, edge in enumerate(edges):
        prefix = f"action-graph.edges[{index}]"
        if not isinstance(edge, dict):
            errors.append(f"{prefix} must be an object")
            continue
        if edge.get("kind") not in EDGE_KINDS:
            errors.append(f"{prefix}.kind is invalid")
        if edge.get("from") not in node_ids or edge.get("to") not in node_ids:
            errors.append(f"{prefix} references an unknown node")
    return valid_nodes


def _validate_cli(cli: object, evidence_ids: set[str], errors: list[str]) -> list[dict[str, Any]]:
    if not _is_object(cli, "cli.json", errors):
        return []
    commands = cli.get("commands", [])
    if not isinstance(commands, list):
        errors.append("cli.commands must be an array")
        return []
    required = {
        "id", "executable_ref", "version_evidence", "arguments_schema",
        "stdout_schema", "exit_codes", "side_effect", "timeout_ms", "evidence",
    }
    ids: set[str] = set()
    for index, command in enumerate(commands):
        if not isinstance(command, dict):
            errors.append(f"cli.commands[{index}] must be an object")
            continue
        missing = required - set(command)
        if missing:
            errors.append(f"cli.commands[{index}] missing {sorted(missing)}")
        command_id = command.get("id")
        if not isinstance(command_id, str) or not command_id:
            errors.append(f"cli.commands[{index}].id must be a non-empty string")
        elif command_id in ids:
            errors.append(f"cli.commands[{index}].id is duplicated")
        else:
            ids.add(command_id)
        executable_ref = command.get("executable_ref")
        if (
            not isinstance(executable_ref, str)
            or not executable_ref
            or not EXECUTABLE_REFERENCE.fullmatch(executable_ref)
            or ".." in executable_ref.split("/")
        ):
            errors.append(f"cli.commands[{index}].executable_ref is unsafe")
        if not isinstance(command.get("arguments_schema"), dict):
            errors.append(f"cli.commands[{index}].arguments_schema must be an object")
        if not isinstance(command.get("stdout_schema"), dict):
            errors.append(f"cli.commands[{index}].stdout_schema must be an object")
        if command.get("side_effect") not in SIDE_EFFECTS:
            errors.append(f"cli.commands[{index}].side_effect is invalid")
        timeout = command.get("timeout_ms")
        if isinstance(timeout, bool) or not isinstance(timeout, int) or not 0 < timeout <= 300_000:
            errors.append(f"cli.commands[{index}].timeout_ms must be an integer from 1 to 300000")
        exit_codes = command.get("exit_codes")
        if not isinstance(exit_codes, dict):
            errors.append(f"cli.commands[{index}].exit_codes must be an object")
        else:
            if "0" not in exit_codes or not isinstance(exit_codes.get("0"), str) or not exit_codes.get("0", "").strip():
                errors.append(f"cli.commands[{index}].exit_codes must include success code 0")
            for code, meaning in exit_codes.items():
                if not isinstance(code, str) or not code.isdigit() or not 0 <= int(code) <= 255:
                    errors.append(f"cli.commands[{index}].exit code key is invalid: {code}")
                if not isinstance(meaning, str) or not meaning.strip():
                    errors.append(f"cli.commands[{index}].exit code meaning must be a non-empty string: {code}")
        command_evidence_value = command.get("evidence", [])
        command_evidence = command_evidence_value if isinstance(command_evidence_value, list) else []
        if not isinstance(command_evidence_value, list):
            errors.append(f"cli.commands[{index}].evidence must be an array")
        for evidence_id in command_evidence:
            if evidence_id not in evidence_ids:
                errors.append(f"cli.commands[{index}] references unknown evidence: {evidence_id}")
        version_evidence = command.get("version_evidence")
        if version_evidence not in evidence_ids:
            errors.append(f"cli.commands[{index}].version_evidence references unknown evidence: {version_evidence}")
    return [command for command in commands if isinstance(command, dict)]


def derive_coverage(
    operations: dict[str, dict[str, Any]],
    nodes: list[dict[str, Any]],
    valid_evidence: set[str],
) -> dict[str, dict[str, int]]:
    node_by_operation: dict[str, list[dict[str, Any]]] = {}
    for node in nodes:
        node_operations = node.get("operations", [])
        for operation_id in node_operations if isinstance(node_operations, list) else []:
            node_by_operation.setdefault(operation_id, []).append(node)
    observed_routes = 0
    verified_routes = 0
    for operation_id, operation in operations.items():
        linked = node_by_operation.get(operation_id, [])
        marker_evidence_value = operation.get("x-mcp", {}).get("evidence", [])
        marker_evidence = marker_evidence_value if isinstance(marker_evidence_value, list) else []
        evidence = set(marker_evidence)
        for node in linked:
            node_evidence = node.get("evidence", [])
            evidence.update(node_evidence if isinstance(node_evidence, list) else [])
        if evidence:
            observed_routes += 1
        if evidence and evidence <= valid_evidence and any(node.get("confidence") == "verified" for node in linked):
            verified_routes += 1
    observed_nodes = [node for node in nodes if isinstance(node.get("evidence"), list) and node.get("evidence")]
    verified_nodes = [
        node for node in observed_nodes
        if node.get("confidence") == "verified" and set(node.get("evidence", [])) <= valid_evidence
    ]
    return {
        "route_counts": {
            "observed": observed_routes,
            "modeled": len(operations),
            "verified": verified_routes,
        },
        "action_counts": {
            "observed": len(observed_nodes),
            "native": sum(node.get("native") == "yes" for node in nodes),
            "verified": len(verified_nodes),
        },
    }


def _validate_coverage(
    coverage: object,
    operations: dict[str, dict[str, Any]],
    nodes: list[dict[str, Any]],
    valid_evidence: set[str],
    errors: list[str],
) -> None:
    if not _is_object(coverage, "coverage.json", errors):
        return
    derived = derive_coverage(operations, nodes, valid_evidence)
    for field, expected in derived.items():
        if coverage.get(field) != expected:
            errors.append(f"coverage.{field} does not match derived coverage: {expected}")
    if not isinstance(coverage.get("gaps"), list):
        errors.append("coverage.gaps must be a list")


def _validate_gaps(
    coverage: object,
    evidence_ids: set[str],
    valid_evidence: set[str],
    level: str,
    capability_ids: set[str],
    errors: list[str],
) -> set[str]:
    if not isinstance(coverage, dict):
        return set()
    gaps = coverage.get("gaps", [])
    if not isinstance(gaps, list):
        errors.append("coverage.gaps must be an array")
        return set()
    ids: set[str] = set()
    covered: set[str] = set()
    for index, gap in enumerate(gaps):
        prefix = f"coverage.gaps[{index}]"
        if not isinstance(gap, dict):
            errors.append(f"{prefix} must be an object")
            continue
        if level in {"build", "release"}:
            missing = GAP_REQUIRED - set(gap)
            if missing:
                errors.append(f"{prefix} missing required fields: {sorted(missing)}")
        if "evidence" in gap:
            _check_evidence_refs(gap.get("evidence"), f"{prefix}.evidence", evidence_ids, errors)
        gap_id = gap.get("id")
        if not isinstance(gap_id, str) or not gap_id.strip():
            errors.append(f"{prefix}.id must be a non-empty string")
        if gap_id in ids:
            errors.append(f"{prefix} gap id is duplicated: {gap_id}")
        elif isinstance(gap_id, str) and gap_id:
            ids.add(gap_id)
        capability = gap.get("capability")
        if not isinstance(capability, str) or capability not in capability_ids:
            errors.append(f"{prefix}.capability does not resolve: {capability}")
        elif capability in covered:
            errors.append(f"{prefix}.capability is duplicated: {capability}")
        else:
            covered.add(capability)
        if gap.get("disposition") not in GAP_DISPOSITIONS:
            errors.append(f"{prefix}.disposition is invalid")
        for field in ("impact", "workaround", "owner"):
            if not isinstance(gap.get(field), str) or not gap.get(field, "").strip():
                errors.append(f"{prefix}.{field} must be a non-empty string")
        disposition = gap.get("disposition")
        gap_evidence = gap.get("evidence", [])
        if disposition in {"open", "deferred", "unsupported"} and (
            not isinstance(gap_evidence, list)
            or not gap_evidence
            or not set(gap_evidence) <= valid_evidence
        ):
            errors.append(
                f"{prefix} {disposition} disposition requires non-empty valid evidence"
            )
    return covered


def validate(root: Path, level: str = "structure") -> list[str]:
    errors: list[str] = []
    project = root.expanduser().absolute()
    workspace = project / ".website-mcp"
    if workspace.is_symlink():
        return ["workspace path is a symlink"]
    if not workspace.is_dir():
        return ["missing .website-mcp directory"]
    symlinks = [str(path.relative_to(workspace)) for path in workspace.rglob("*") if path.is_symlink()]
    if symlinks:
        return [f"workspace contains symlink: {name}" for name in sorted(symlinks)]
    missing = REQUIRED - {item.name for item in workspace.iterdir()}
    errors.extend(f"missing {name}" for name in sorted(missing))
    if missing:
        return errors
    try:
        state = load(workspace / "state.json")
        auth = load(workspace / "auth.json")
        cli = load(workspace / "cli.json")
        openapi = load(workspace / "openapi.json")
        graph = load(workspace / "action-graph.json")
        evidence = load(workspace / "evidence-index.json")
        coverage = load(workspace / "coverage.json")
        for filename in ("checkpoints.jsonl", "discovery-iterations.jsonl"):
            read_jsonl(workspace / filename)
    except ValueError as exc:
        return [str(exc)]

    def origin(value: object) -> tuple[str, str, int] | None:
        if not isinstance(value, str):
            return None
        parsed = urlparse(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.params
            or parsed.query
            or parsed.fragment
        ):
            return None
        return (parsed.scheme.lower(), parsed.hostname.lower(), parsed.port or (443 if parsed.scheme.lower() == "https" else 80))

    target = state.get("target") if isinstance(state, dict) else None
    try:
        kind = target_kind(target) if isinstance(target, str) else None
    except ValueError:
        kind = None
    if kind == "cli":
        if isinstance(openapi, dict):
            if openapi.get("servers") != []:
                errors.append("CLI-only openapi.servers must be an empty array")
            if openapi.get("paths") != {}:
                errors.append("CLI-only openapi.paths must be an empty object")
    else:
        target_origin = origin(target) if isinstance(target, str) else None
        if target_origin is None:
            errors.append("state.target must be a credential-free HTTP(S) origin or cli://local")
        if isinstance(openapi, dict):
            servers = openapi.get("servers")
            if not isinstance(servers, list) or not servers:
                errors.append("openapi.servers must declare state.target origin")
            else:
                for index, server in enumerate(servers):
                    if not isinstance(server, dict) or origin(server.get("url")) != target_origin:
                        errors.append(f"openapi.servers[{index}] must match state.target origin")

    known_evidence, hash_valid_evidence = _valid_evidence(workspace, evidence, errors)
    evidence_records_value = evidence.get("records", []) if isinstance(evidence, dict) else []
    if not isinstance(evidence_records_value, list):
        evidence_records_value = []
    evidence_records = {
        record.get("id"): record
        for record in evidence_records_value
        if isinstance(record, dict) and isinstance(record.get("id"), str)
    }
    if isinstance(state, dict):
        _validate_history(state, known_evidence, errors)
    else:
        errors.append("state.json must be an object")
    for document, label in (
        (openapi, "openapi.json"),
        (graph, "action-graph.json"),
        (cli, "cli.json"),
        (auth, "auth.json"),
        (coverage, "coverage.json"),
    ):
        _validate_refs(document, label, errors)
    operation_ids, operations = _validate_openapi(openapi, known_evidence, errors)
    auth_ids = _validate_auth(auth, known_evidence, errors)
    commands = _validate_cli(cli, known_evidence, errors)
    command_ids = {
        command.get("id") for command in commands if isinstance(command.get("id"), str)
    }
    nodes = _validate_graph(
        graph,
        operation_ids,
        command_ids,
        auth_ids,
        known_evidence,
        hash_valid_evidence,
        evidence_records,
        level,
        errors,
    )
    node_ids = {node.get("id") for node in nodes if isinstance(node.get("id"), str)}
    capability_ids = operation_ids | command_ids | node_ids
    gap_capabilities = _validate_gaps(
        coverage,
        known_evidence,
        hash_valid_evidence,
        level,
        capability_ids,
        errors,
    )
    errors.extend(scan_workspace(workspace))

    if isinstance(state, dict):
        state_stages_value = state.get("stages", [])
        state_stages = state_stages_value if isinstance(state_stages_value, list) else []
        stage_status = {
            stage.get("id"): stage.get("status")
            for stage in state_stages
            if isinstance(stage, dict)
        }
        root_security = openapi.get("security", []) if isinstance(openapi, dict) else []
        protected = any(
            bool(operation["security"] if "security" in operation else root_security)
            for operation in operations.values()
        )
        discovery_advanced = stage_status.get("discover") == "complete" or any(
            stage_status.get(stage) in {"in_progress", "blocked", "complete"}
            for stage in ("model", "specify", "implement", "verify", "agent-evaluate", "harden")
        )
        if protected and discovery_advanced and stage_status.get("auth") != "complete":
            errors.append("protected discovery cannot advance until auth is complete")

    if level in {"build", "release"}:
        _validate_coverage(coverage, operations, nodes, hash_valid_evidence, errors)
        if not operations and not nodes and not commands:
            errors.append("build requires at least one modeled capability")
        if not nodes:
            errors.append("build action graph must contain at least one capability node")
        bound_operations: set[str] = set()
        bound_commands: set[str] = set()
        unreconciled: set[str] = set()
        for node in nodes:
            node_operations = node.get("operations", [])
            node_commands = node.get("commands", [])
            bound_operations.update(node_operations if isinstance(node_operations, list) else [])
            bound_commands.update(node_commands if isinstance(node_commands, list) else [])
            if node.get("confidence") != "verified" or node.get("native") != "yes":
                if isinstance(node.get("id"), str):
                    unreconciled.add(node["id"])
        unreconciled.update(operation_ids - bound_operations)
        unreconciled.update(command_ids - bound_commands)
        for capability in sorted(unreconciled - gap_capabilities):
            errors.append(f"unreconciled capability requires a structured gap: {capability}")
    else:
        if not isinstance(coverage, dict) or not isinstance(coverage.get("gaps"), list):
            errors.append("coverage.gaps must be a list")
    if level == "release" and isinstance(state, dict):
        _validate_release_proofs(state, auth, evidence, hash_valid_evidence, errors)
        release_stages_value = state.get("stages", [])
        release_stages = release_stages_value if isinstance(release_stages_value, list) else []
        incomplete = [
            stage.get("id")
            for stage in release_stages
            if isinstance(stage, dict) and stage.get("status") != "complete"
        ]
        if incomplete:
            errors.append(f"release requires all stages complete: {', '.join(str(x) for x in incomplete)}")
        capability_evidence: set[str] = set()
        for operation in operations.values():
            marker = operation.get("x-mcp", {})
            route_evidence = marker.get("evidence", []) if isinstance(marker, dict) else []
            capability_evidence.update(route_evidence if isinstance(route_evidence, list) else [])
        for node in nodes:
            node_evidence = node.get("evidence", [])
            capability_evidence.update(node_evidence if isinstance(node_evidence, list) else [])
        for command in commands:
            command_evidence = command.get("evidence", [])
            capability_evidence.update(command_evidence if isinstance(command_evidence, list) else [])
        if not capability_evidence or not capability_evidence <= hash_valid_evidence:
            errors.append("release requires capability evidence with valid hashes")
    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("project", type=Path)
    parser.add_argument("--level", choices=["structure", "build", "release"], default="structure")
    args = parser.parse_args()
    errors = validate(args.project, args.level)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"website MCP workspace is valid at {args.level} level")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
