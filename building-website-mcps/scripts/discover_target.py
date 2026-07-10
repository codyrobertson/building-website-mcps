#!/usr/bin/env python3
"""Iteratively discover a website's public evidence and compile MCP artifacts."""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urljoin

from scaffold_workspace import target_kind
from site_to_mcp.checkpoints import approved, invalidate_many
from site_to_mcp.common import (
    ensure_workspace_safe,
    has_url_userinfo,
    read_jsonl,
    redact_text,
    same_origin,
)
from site_to_mcp.compiler import Compiler, record_iteration


class MaterialChangePreflightError(ValueError):
    """A material change could not invalidate downstream state safely."""


def _invalidate_state(skill_scripts: Path, project: Path, evidence_id: str) -> None:
    state = json.loads((project / ".website-mcp" / "state.json").read_text(encoding="utf-8"))
    statuses = {
        stage.get("id"): stage.get("status")
        for stage in state.get("stages", [])
        if isinstance(stage, dict)
    }
    if statuses.get("discover") != "complete" and statuses.get("model") != "complete":
        return
    command = [
        sys.executable,
        str(skill_scripts / "transition_stage.py"),
        str(project),
        "discover",
        "invalidate",
        "--reason",
        "material discovery evidence changed",
    ]
    command.extend(["--evidence", evidence_id])
    result = subprocess.run(command, capture_output=True, text=True, timeout=10)
    if result.returncode != 0:
        raise MaterialChangePreflightError(
            f"could not reopen discovery/model: {result.stderr.strip()}"
        )


def _error_code(exc: BaseException) -> str:
    message = str(exc).lower()
    if "workspace" in message or "jsonl path" in message:
        return "unsafe_workspace"
    if "evidence-index" in message:
        return "malformed_evidence_index"
    if "cli contract" in message:
        return "malformed_cli"
    if "openapi" in message:
        return "malformed_openapi"
    if "html" in message:
        return "malformed_html"
    if "same-origin" in message or "credential-free" in message:
        return "unsafe_discovery_url"
    return "discovery_failure"


def _error_output(exc: BaseException) -> str:
    message, _ = redact_text(str(exc))
    code = _error_code(exc)
    return json.dumps(
        {
            "status": "discovery_error",
            "error": {"code": code, "message": message},
            "gaps": [{"kind": code, "disposition": "open"}],
        },
        sort_keys=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("project", type=Path)
    parser.add_argument("target")
    parser.add_argument("--openapi")
    parser.add_argument("--cli-contract", type=Path)
    args = parser.parse_args()
    project = args.project.expanduser().resolve()
    workspace = project / ".website-mcp"
    workspace_safe = False
    try:
        kind = target_kind(args.target)
        if has_url_userinfo(args.target):
            raise ValueError("target must be credential-free")
        if kind == "cli" and args.openapi:
            raise ValueError("CLI-only targets do not accept --openapi")
        if kind == "cli" and args.cli_contract is None:
            raise ValueError("CLI-only targets require --cli-contract")
        ensure_workspace_safe(workspace)
        workspace_safe = True
        state = json.loads((workspace / "state.json").read_text(encoding="utf-8"))
        if state.get("target", "").rstrip("/") != args.target.rstrip("/"):
            raise ValueError("target does not match the authorized workspace target")
        if kind == "http" and args.openapi:
            candidate = urljoin(args.target.rstrip("/") + "/", args.openapi)
            if not same_origin(args.target, candidate):
                raise ValueError("explicit OpenAPI URL must be same-origin")
        if not approved(workspace, "scope"):
            record_iteration(
                workspace,
                args.target,
                result="awaiting_checkpoint",
                evidence=[],
                model_changes=[],
                next_probe="Obtain explicit scope approval bound to spec.md",
                evidence_digest=None,
            )
            print(json.dumps({"status": "awaiting_checkpoint", "checkpoint": "scope"}))
            return 3

        previous_iterations = read_jsonl(workspace / "discovery-iterations.jsonl")
        previous_iteration = next(
            (
                record
                for record in reversed(previous_iterations)
                if record.get("evidence_digest")
            ),
            None,
        )
        previous_digest = previous_iteration.get("evidence_digest") if previous_iteration else None
        compiler = Compiler(project, args.target)
        if kind == "cli":
            digest, auth_required = compiler.compile_cli(args.cli_contract)
        else:
            source, openapi_evidence, _ = compiler.observe(args.openapi)
            digest, auth_required = compiler.compile(source, openapi_evidence, args.cli_contract)
        if previous_digest and previous_digest != digest:
            previous_evidence = set(previous_iteration.get("evidence", []))
            changed_evidence = next(
                (item for item in compiler.evidence_ids if item not in previous_evidence),
                compiler.evidence_ids[-1],
            )
            transition_evidence = next(iter(previous_evidence), changed_evidence)
            _invalidate_state(Path(__file__).resolve().parent, project, transition_evidence)
            invalidate_many(
                workspace,
                ["native-floor", "final"],
                "material discovery evidence changed",
            )

        required = (["auth"] if auth_required else []) + ["native-floor", "final"]
        missing = [checkpoint for checkpoint in required if not approved(workspace, checkpoint)]
        if compiler.coverage is None:
            raise ValueError("compiled discovery candidate is missing coverage")
        result = "partial" if compiler.coverage["gaps"] else "confirmed"
        next_probe = (
            f"Obtain explicit {missing[0]} checkpoint approval"
            if missing
            else "Proceed to implementation planning; no write probe was inferred"
        )
        compiler.commit()
        record_iteration(
            workspace,
            args.target,
            result=result,
            evidence=list(dict.fromkeys(compiler.evidence_ids)),
            model_changes=compiler.model_changes,
            next_probe=next_probe,
            evidence_digest=digest,
        )
        if missing:
            print(json.dumps({"status": "awaiting_checkpoint", "checkpoint": missing[0]}))
            return 3
        print(json.dumps({"status": "complete", "result": result}))
        return 0
    except MaterialChangePreflightError as exc:
        print(_error_output(exc), file=sys.stderr)
        return 2
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        if workspace_safe:
            try:
                record_iteration(
                    workspace,
                    args.target,
                    result="discovery_error",
                    evidence=[],
                    model_changes=[],
                    next_probe="Correct the malformed or unsafe discovery input before retrying",
                    evidence_digest=None,
                )
            except (OSError, ValueError, json.JSONDecodeError):
                pass
        print(_error_output(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
