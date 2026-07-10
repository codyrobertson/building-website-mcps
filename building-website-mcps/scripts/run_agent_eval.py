#!/usr/bin/env python3
"""Record durable, structured cold-agent evaluation evidence.

This recorder validates the shape and durability of an agent-session trace. It
does not independently attest that a supplied command was a real LLM session;
the resulting report keeps runner provenance explicit. Deterministic, fixture,
scripted, and fake runners are recorded as rejected non-agent evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from run_fixture_matrix import EvidenceError, redact_value, write_json


SCRIPTED_PROBES = {"mcp_probe.py", "run_fixture_matrix.py", "benchmark_mcp.py"}
TRACE_SCHEMA_VERSION = 1
ACTUAL_AGENT_RUNNERS = {"external_agent", "collaboration_agent"}
REJECTED_RUNNER_WORDS = {"deterministic", "fake", "fixture", "scripted", "probe"}
SHA256 = re.compile(r"^[a-f0-9]{64}$")


class AgentTraceError(EvidenceError):
    """A supplied result is not a durable actual-agent trace."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _non_empty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AgentTraceError(f"agent_trace_schema_requires_nonempty_{field}")
    return value.strip()


def _non_negative_number(value: Any, field: str) -> float | int:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise AgentTraceError(f"agent_trace_schema_requires_nonnegative_{field}")
    return value


def _non_negative_integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AgentTraceError(f"agent_trace_schema_requires_nonnegative_integer_{field}")
    return value


def _require_object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AgentTraceError(f"agent_trace_schema_requires_object_{field}")
    return value


def _require_nonempty_string_list(value: Any, field: str, index: int) -> list[str]:
    if not isinstance(value, list) or not value or any(not isinstance(item, str) or not item.strip() for item in value):
        raise EvidenceError(f"agent case {index} requires a non-empty {field} string array")
    return [item.strip() for item in value]


def load_cases(path: Path) -> list[dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError("agent case file must be valid JSON") from exc
    if not isinstance(value, list) or not value:
        raise EvidenceError("agent case file must be a non-empty JSON array")
    cases: list[dict[str, Any]] = []
    ids: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise EvidenceError(f"agent case {index} must be an object")
        case = {key: item.get(key) for key in ("id", "scenario", "scope", "task")}
        if any(not isinstance(candidate, str) or not candidate.strip() for candidate in case.values()):
            raise EvidenceError(f"agent case {index} requires non-empty id, scenario, scope, and task strings")
        case_id = str(case["id"])
        if case_id in ids:
            raise EvidenceError(f"agent case id is duplicated: {case_id}")
        ids.add(case_id)
        cases.append(
            {
                **{key: str(candidate).strip() for key, candidate in case.items()},
                "success_criteria": _require_nonempty_string_list(item.get("success_criteria"), "success_criteria", index),
                "safety_requirements": _require_nonempty_string_list(item.get("safety_requirements"), "safety_requirements", index),
            }
        )
    return cases


def parse_agent_command(value: str) -> list[str]:
    try:
        command = shlex.split(value)
    except ValueError as exc:
        raise EvidenceError("--agent-command is not a valid command line") from exc
    if not command:
        raise EvidenceError("--agent-command is required")
    names = {Path(part).name for part in command}
    if names & SCRIPTED_PROBES:
        raise EvidenceError("scripted probes are not agent evaluations; use run_fixture_matrix.py instead")
    return command


def agent_environment(home: Path) -> dict[str, str]:
    # Keep the invocation cold and do not leak fixture credentials, approvals,
    # browser state, or caller-specific Python imports into the external agent.
    return {
        "HOME": str(home),
        "PATH": os.environ.get("PATH", ""),
        "LANG": os.environ.get("LANG", "C"),
        "LC_ALL": os.environ.get("LC_ALL", "C"),
        "PYTHONPATH": "",
        "TMPDIR": str(home / "tmp"),
    }


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _inline_transcript(value: Any) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return bool(value) and all(isinstance(item, dict) and item for item in value)
    return False


def _record_transcript_artifact(value: Any, evidence_dir: Path, transcript_output: Path) -> dict[str, str]:
    artifact = _require_object(value, "transcript_artifact")
    supplied_path = _non_empty_string(artifact.get("path"), "transcript_artifact_path")
    expected_digest = _non_empty_string(artifact.get("sha256"), "transcript_artifact_sha256").lower()
    if not SHA256.fullmatch(expected_digest):
        raise AgentTraceError("agent_trace_schema_requires_sha256_transcript_artifact_digest")
    source = (evidence_dir / supplied_path).resolve()
    if not _is_within(source, evidence_dir.resolve()) or not source.is_file():
        raise AgentTraceError("agent_trace_schema_requires_durable_transcript_artifact")
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_digest:
        raise AgentTraceError("agent_trace_schema_transcript_artifact_digest_mismatch")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AgentTraceError("agent_trace_schema_requires_utf8_transcript_artifact") from exc
    # The output file is the durable, display-safe copy. Delete the runner's
    # original so the recorder never leaves an unredacted transcript behind.
    safe_text = redact_value(text)
    if not isinstance(safe_text, str) or not safe_text.strip():
        raise AgentTraceError("agent_trace_schema_requires_nonempty_transcript_artifact")
    transcript_output.write_text(safe_text, encoding="utf-8")
    if source != transcript_output:
        source.unlink()
    return {"path": str(transcript_output), "sha256": hashlib.sha256(safe_text.encode("utf-8")).hexdigest()}


def _validate_tool_calls(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise AgentTraceError("agent_trace_schema_requires_at_least_one_structured_tool_call")
    calls: list[dict[str, Any]] = []
    for index, call in enumerate(value):
        call = _require_object(call, f"tool_calls_{index}")
        name = _non_empty_string(call.get("name"), f"tool_calls_{index}_name")
        arguments = call.get("arguments")
        if not isinstance(arguments, dict):
            raise AgentTraceError(f"agent_trace_schema_requires_object_tool_calls_{index}_arguments")
        status = call.get("status")
        if status not in {"success", "failure"}:
            raise AgentTraceError(f"agent_trace_schema_requires_success_or_failure_tool_calls_{index}_status")
        calls.append(
            {
                "name": name,
                "arguments": arguments,
                "status": status,
                "duration_ms": _non_negative_number(call.get("duration_ms"), f"tool_calls_{index}_duration_ms"),
                "request_bytes": _non_negative_integer(call.get("request_bytes"), f"tool_calls_{index}_request_bytes"),
                "response_bytes": _non_negative_integer(call.get("response_bytes"), f"tool_calls_{index}_response_bytes"),
            }
        )
    return calls


def _validate_safety_decisions(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise AgentTraceError("agent_trace_schema_requires_nonempty_safety_decisions")
    decisions: list[dict[str, str]] = []
    for index, decision in enumerate(value):
        decision = _require_object(decision, f"safety_decisions_{index}")
        action = decision.get("action")
        if action not in {"proceed", "confirm", "refuse", "recover", "stop"}:
            raise AgentTraceError(f"agent_trace_schema_requires_safety_action_safety_decisions_{index}")
        decisions.append(
            {
                "decision": _non_empty_string(decision.get("decision"), f"safety_decisions_{index}_decision"),
                "action": action,
                "rationale": _non_empty_string(decision.get("rationale"), f"safety_decisions_{index}_rationale"),
            }
        )
    return decisions


def validate_agent_trace(value: Any, case: dict[str, Any], evidence_dir: Path, transcript_output: Path) -> tuple[dict[str, Any], str]:
    """Validate and normalize one agent trace, retaining only durable evidence."""
    trace = _require_object(value, "root")
    if trace.get("schema_version") != TRACE_SCHEMA_VERSION:
        raise AgentTraceError("agent_trace_schema_requires_schema_version_1")
    if trace.get("evidence_kind") != "agent_session_trace":
        raise AgentTraceError("agent_trace_schema_requires_agent_session_trace_evidence_kind")

    runner = _require_object(trace.get("runner"), "runner")
    runner_kind = _non_empty_string(runner.get("kind"), "runner_kind")
    if runner.get("deterministic") is not False or any(word in runner_kind.lower() for word in REJECTED_RUNNER_WORDS):
        raise AgentTraceError("deterministic_or_fake_runner_is_not_actual_agent_evidence")
    if runner_kind not in ACTUAL_AGENT_RUNNERS:
        raise AgentTraceError("unrecognized_runner_kind_is_not_actual_agent_evidence")
    if runner.get("cold_context") is not True:
        raise AgentTraceError("agent_trace_schema_requires_cold_context_true")
    session_id = _non_empty_string(runner.get("session_id"), "runner_session_id")

    agent = _require_object(trace.get("agent"), "agent")
    if trace.get("task") != case["task"]:
        raise AgentTraceError("agent_trace_schema_task_must_match_supplied_task")
    normalized: dict[str, Any] = {
        "schema_version": TRACE_SCHEMA_VERSION,
        "evidence_kind": "agent_session_trace",
        "runner": {
            "kind": runner_kind,
            "deterministic": False,
            "cold_context": True,
            "session_id": session_id,
        },
        "agent": {
            "identity": _non_empty_string(agent.get("identity"), "agent_identity"),
            "version": _non_empty_string(agent.get("version"), "agent_version"),
        },
        "case_id": case["id"],
        "scenario": case["scenario"],
        "task": case["task"],
        "tool_calls": _validate_tool_calls(trace.get("tool_calls")),
        "safety_decisions": _validate_safety_decisions(trace.get("safety_decisions")),
    }

    if _inline_transcript(trace.get("transcript")):
        normalized["transcript"] = trace["transcript"]
    elif "transcript_artifact" in trace:
        normalized["transcript_artifact"] = _record_transcript_artifact(
            trace["transcript_artifact"], evidence_dir, transcript_output
        )
    else:
        raise AgentTraceError("agent_trace_schema_requires_transcript_or_durable_transcript_artifact")

    outcome = _require_object(trace.get("outcome"), "outcome")
    if outcome.get("status") not in {"success", "failure"}:
        raise AgentTraceError("agent_trace_schema_requires_success_or_failure_outcome_status")
    normalized["outcome"] = {
        "status": outcome["status"],
        "summary": _non_empty_string(outcome.get("summary"), "outcome_summary"),
    }
    timing = _require_object(trace.get("timing"), "timing")
    bytes_used = _require_object(trace.get("bytes"), "bytes")
    normalized["timing"] = {"duration_ms": _non_negative_number(timing.get("duration_ms"), "timing_duration_ms")}
    normalized["bytes"] = {
        "input": _non_negative_integer(bytes_used.get("input"), "bytes_input"),
        "output": _non_negative_integer(bytes_used.get("output"), "bytes_output"),
    }
    return normalized, f"{runner_kind}_evidence"


def _failed_report(case: dict[str, Any], trace_path: Path, reason: str, *, trace: dict[str, Any]) -> dict[str, str]:
    write_json(trace_path, trace)
    return {
        "id": case["id"],
        "status": "failed",
        "reason": reason,
        "trace": str(trace_path),
        "proof_status": "rejected_not_actual_agent_evidence",
    }


def _discard_untrusted_evidence_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def run_case(command: list[str], package: Path, case: dict[str, Any], trace_root: Path, timeout: float) -> dict[str, str]:
    trace_path = trace_root / f"{case['id']}.json"
    evidence_dir = trace_root / f"{case['id']}-evidence"
    evidence_dir.mkdir(parents=True, exist_ok=False)
    transcript_output = trace_root / f"{case['id']}.transcript.txt"
    with tempfile.TemporaryDirectory(prefix="website-mcp-agent-") as temporary:
        sandbox = Path(temporary)
        home = sandbox / "home"
        (home / "tmp").mkdir(parents=True)
        request = {
            "task": case["task"],
            "scope": case["scope"],
            "generated_package": str(package),
            "companion_skill": str(package / "skill" / "SKILL.md"),
            "protocol_version": "2025-06-18",
            "evidence_dir": str(evidence_dir),
        }
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                input=json.dumps(request),
                text=True,
                capture_output=True,
                cwd=sandbox,
                env=agent_environment(home),
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            trace = {
                "case_id": case["id"],
                "kind": "cold_agent_trace_recording",
                "status": "failed",
                "reason": "agent_timeout",
                "recorded_timing": {"duration_ms": round((time.monotonic() - started) * 1000, 3)},
                "recorded_bytes": {"stdout": len((exc.stdout or "").encode("utf-8")), "stderr": len((exc.stderr or "").encode("utf-8"))},
            }
            _discard_untrusted_evidence_dir(evidence_dir)
            return _failed_report(case, trace_path, "agent_timeout", trace=trace)
    duration = round((time.monotonic() - started) * 1000, 3)
    recording = {
        "case_id": case["id"],
        "kind": "cold_agent_trace_recording",
        "recorded_timing": {"duration_ms": duration},
        "recorded_bytes": {
            "request": len(json.dumps(request).encode("utf-8")),
            "stdout": len(completed.stdout.encode("utf-8")),
            "stderr": len(completed.stderr.encode("utf-8")),
        },
        "returncode": completed.returncode,
        "provided_input_keys": sorted(request),
    }
    if completed.returncode != 0:
        recording.update({"status": "failed", "reason": f"agent_exit_{completed.returncode}", "stderr": completed.stderr})
        _discard_untrusted_evidence_dir(evidence_dir)
        return _failed_report(case, trace_path, f"agent_exit_{completed.returncode}", trace=recording)
    if len(completed.stdout.encode("utf-8")) > 1024 * 1024:
        recording.update({"status": "failed", "reason": "agent_stdout_exceeds_1MiB", "stderr": completed.stderr})
        _discard_untrusted_evidence_dir(evidence_dir)
        return _failed_report(case, trace_path, "agent_stdout_exceeds_1MiB", trace=recording)
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError:
        recording.update({"status": "failed", "reason": "agent_trace_schema_requires_single_json_object", "stderr": completed.stderr})
        _discard_untrusted_evidence_dir(evidence_dir)
        return _failed_report(case, trace_path, "agent_trace_schema_requires_single_json_object", trace=recording)
    try:
        agent_trace, evidence_class = validate_agent_trace(result, case, evidence_dir, transcript_output)
    except AgentTraceError as exc:
        recording.update({"status": "failed", "reason": exc.reason, "stderr": completed.stderr})
        return _failed_report(case, trace_path, exc.reason, trace=recording)
    finally:
        # A runner may have created support files beside its transcript. They
        # are untrusted and are never release artifacts.
        _discard_untrusted_evidence_dir(evidence_dir)
    status = "ok" if agent_trace["outcome"]["status"] == "success" else "failed"
    reason = None if status == "ok" else "agent_reported_failure"
    recording.update({"status": status, "reason": reason, "agent_trace": agent_trace, "stderr": completed.stderr})
    write_json(trace_path, recording)
    report = {
        "id": case["id"],
        "status": status,
        "trace": str(trace_path),
        "evidence_class": evidence_class,
        "proof_status": "structurally_valid_not_independently_attested",
    }
    if reason:
        report["reason"] = reason
    return report


def evaluate(package: Path, cases_path: Path, command_text: str, output: Path, *, timeout: float) -> dict[str, Any]:
    package = package.expanduser().resolve()
    if not (package / "server.py").is_file() or not (package / "skill" / "SKILL.md").is_file():
        raise EvidenceError("generated package must contain server.py and companion skill/SKILL.md")
    cases = load_cases(cases_path.expanduser())
    command = parse_agent_command(command_text)
    trace_root = output.expanduser().resolve().parent / "agent-eval-traces"
    trace_root.mkdir(parents=True, exist_ok=True)
    reports = [run_case(command, package, case, trace_root, timeout) for case in cases]
    result = {
        "version": TRACE_SCHEMA_VERSION,
        "evaluation_kind": "cold_agent_trace_recording",
        "claim": "structural validation only; runner provenance is not independently verified",
        "status": "ok" if all(item["status"] == "ok" for item in reports) else "failed",
        "cases": reports,
    }
    write_json(output.expanduser().resolve(), result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generated-package", type=Path, required=True)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--agent-command", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    try:
        if args.timeout <= 0:
            raise EvidenceError("--timeout must be positive")
        result = evaluate(args.generated_package, args.cases, args.agent_command, args.output, timeout=args.timeout)
    except (OSError, EvidenceError, ValueError) as exc:
        print(redact_value(str(exc)), file=sys.stderr)
        return 2
    print(json.dumps({"status": result["status"], "output": str(args.output.expanduser().resolve())}, sort_keys=True))
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
