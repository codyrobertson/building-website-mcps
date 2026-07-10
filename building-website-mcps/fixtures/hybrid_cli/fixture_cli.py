#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path


PROJECTS = {
    "p-1": {"id": "p-1", "name": "Project One", "event_count": 2},
    "p-2": {"id": "p-2", "name": "Project Two", "event_count": 1},
}


def fail(message: str, code: int = 2) -> None:
    print(json.dumps({"error": message}), file=sys.stderr)
    raise SystemExit(code)


def output_target(value: str) -> Path:
    configured = os.environ.get("FIXTURE_CLI_OUTPUT_ROOT")
    if not configured:
        fail("output_root_not_configured")
    root_input = Path(configured).absolute()
    if root_input.is_symlink():
        fail("output_root_is_symlink")
    try:
        root = root_input.resolve(strict=True)
    except OSError:
        fail("output_root_invalid")
    if not root.is_dir():
        fail("output_root_invalid")
    requested = Path(value)
    if ".." in requested.parts:
        fail("output_path_traversal")
    raw_target = requested if requested.is_absolute() else root_input / requested
    try:
        lexical_parent = raw_target.parent.relative_to(root_input)
        resolved_parent = raw_target.parent.resolve(strict=True)
        resolved_parent.relative_to(root)
    except (OSError, ValueError):
        fail("output_path_outside_root")
    cursor = root_input
    for part in lexical_parent.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            fail("output_path_symlink")
    target = resolved_parent / raw_target.name
    if target.exists() or target.is_symlink():
        fail("output_path_exists")
    return target


def write_exclusive_atomic(target: Path, content: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=".fixture-report.", dir=target.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, target)
        except FileExistsError:
            fail("output_path_exists")
        except OSError:
            fail("output_create_failed")
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(prog="fixture_cli.py")
    parser.add_argument("--version", action="version", version="fixture-cli 1.0.0")
    groups = parser.add_subparsers(dest="group", required=True)
    project = groups.add_parser("project")
    project_actions = project.add_subparsers(dest="action", required=True)
    inspect_command = project_actions.add_parser("inspect")
    inspect_command.add_argument("--id", required=True)
    report = groups.add_parser("report")
    report_actions = report.add_subparsers(dest="action", required=True)
    render = report_actions.add_parser("render")
    render.add_argument("--project", required=True)
    render.add_argument("--output", required=True)
    verify = report_actions.add_parser("verify")
    verify.add_argument("--path", required=True)
    args = parser.parse_args()

    if args.group == "project" and args.action == "inspect":
        value = PROJECTS.get(args.id)
        if value is None:
            fail("project_not_found", 3)
        print(json.dumps(value, sort_keys=True))
        return
    if args.group == "report" and args.action == "render":
        project_value = PROJECTS.get(args.project)
        if project_value is None:
            fail("project_not_found", 3)
        output = output_target(args.output)
        payload = {"format": "fixture-report-v1", "project": project_value}
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        document = {**payload, "sha256": hashlib.sha256(encoded).hexdigest()}
        write_exclusive_atomic(output, json.dumps(document, indent=2) + "\n")
        print(json.dumps({"path": str(output), "bytes": output.stat().st_size}, sort_keys=True))
        return
    if args.group == "report" and args.action == "verify":
        path = Path(args.path)
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            checksum = document.pop("sha256")
            encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
            valid = document.get("format") == "fixture-report-v1" and hashlib.sha256(encoded).hexdigest() == checksum
        except (OSError, json.JSONDecodeError, KeyError):
            valid = False
        print(json.dumps({"path": str(path), "valid": valid}, sort_keys=True))
        raise SystemExit(0 if valid else 4)


if __name__ == "__main__":
    main()
