#!/usr/bin/env python3
"""Contextual secret scanner for website-MCP artifacts.

The scanner reports locations but never includes a suspected value in diagnostics.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from site_to_mcp.common import IDENTIFIER_ASSIGNMENT, is_sensitive_key


MAX_SCAN_BYTES = 2 * 1024 * 1024
REFERENCE = re.compile(
    r"^(?:env:[A-Z_][A-Z0-9_]*|keychain:[A-Za-z0-9._-]+/[A-Za-z0-9._-]+|"
    r"secret-provider:[A-Za-z0-9._/-]+|browser-session:[A-Za-z0-9._-]+)$"
)
KNOWN_SECRET_PATTERNS = [
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\b(?:Bearer|Basic)\s+[A-Za-z0-9+/_.=-]{8,}", re.IGNORECASE),
    re.compile(r"\b(?:sk-|ghp_|github_pat_|AKIA)[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"https?://[^\s/:]+:[^\s/@]+@"),
    re.compile(r"[?&](?:token|api[_-]?key|password|secret)=[^\s&#]+", re.IGNORECASE),
]
SENSITIVE = {
    "authorization",
    "setcookie",
    "cookie",
    "password",
    "passwd",
    "token",
    "accesstoken",
    "refreshtoken",
    "apikey",
    "clientsecret",
    "privatekey",
    "secret",
}
SENSITIVE_ASSIGNMENT = re.compile(
    r"^\s*(?:-\s*)?['\"]?(authorization|set[-_]?cookie|cookie|password|passwd|"
    r"token|access[-_]?token|refresh[-_]?token|api[-_]?key|client[-_]?secret|"
    r"private[-_]?key|secret)['\"]?\s*[:=]\s*(.*?)\s*$",
    re.IGNORECASE,
)
SAFE_ASSIGNMENT = re.compile(
    r"^(?:\$\{[A-Z_][A-Z0-9_]*\}|env:[A-Z_][A-Z0-9_]*|"
    r"\[REDACTED\]|<redacted>|null|['\"]?['\"]?)$",
    re.IGNORECASE,
)


def normalized(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def is_schema_property(path: tuple[str, ...]) -> bool:
    return bool(path) and path[-1] == "properties"


def _is_secret_reference_key(key: str) -> bool:
    key_norm = normalized(key)
    return key == "secret_ref" or (
        key_norm.endswith("ref") and is_sensitive_key(key_norm[:-3])
    )


def _scan_embedded_string(
    value: str, pointer: tuple[str, ...], errors: list[str], filename: str
) -> None:
    label = "/" + "/".join(part.replace("~", "~0").replace("/", "~1") for part in pointer)
    try:
        nested = json.loads(value)
    except json.JSONDecodeError:
        nested = None
    if isinstance(nested, (dict, list)):
        _scan_json(nested, (*pointer, "embedded"), errors, filename)
    for match in re.finditer(r"[?&]([^=&\s]+)=([^&#\s]+)", value):
        key, candidate = match.groups()
        if is_sensitive_key(key) and candidate not in {"[REDACTED]", "<redacted>"}:
            errors.append(f"{filename}:{label}: sensitive URL query key {key} is not permitted")
    for match in IDENTIFIER_ASSIGNMENT.finditer(value):
        key, candidate = match.group("key"), _identifier_value(match)
        if is_sensitive_key(key) and candidate not in {"[REDACTED]", "<redacted>"}:
            errors.append(f"{filename}:{label}: sensitive identifier {key} is not permitted")


def _identifier_value(match: re.Match[str]) -> str:
    for group in ("double_value", "single_value", "bare_value"):
        value = match.group(group)
        if value is not None:
            return value
    return ""


def _scan_json(value: Any, pointer: tuple[str, ...], errors: list[str], filename: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_pointer = (*pointer, str(key))
            label = "/" + "/".join(part.replace("~", "~0").replace("/", "~1") for part in child_pointer)
            key_norm = normalized(str(key))
            is_reference_key = _is_secret_reference_key(str(key))
            if str(key).endswith("_ref") and not isinstance(child, str):
                kind = "secret reference" if is_reference_key else "reference value"
                errors.append(f"{filename}:{label}: invalid {kind}")
            elif is_reference_key and (
                not isinstance(child, str) or not REFERENCE.fullmatch(child)
            ):
                errors.append(f"{filename}:{label}: invalid secret reference")
            elif is_sensitive_key(str(key)) and not is_schema_property(pointer):
                if child not in (None, "", "[REDACTED]", "<redacted>"):
                    errors.append(f"{filename}:{label}: secret-bearing value is not permitted")
            elif (
                pointer
                and is_sensitive_key(pointer[-1])
                and key_norm in {"default", "example", "examples", "const", "enum"}
                and child not in (None, "", [], "[REDACTED]", "<redacted>")
            ):
                errors.append(f"{filename}:{label}: secret-bearing schema example is not permitted")
            _scan_json(child, child_pointer, errors, filename)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _scan_json(child, (*pointer, str(index)), errors, filename)
    elif isinstance(value, str):
        _scan_embedded_string(value, pointer, errors, filename)


def scan_workspace(workspace: Path) -> list[str]:
    errors: list[str] = []
    if workspace.is_symlink():
        return ["workspace path is a symlink"]
    if not workspace.is_dir():
        return ["missing .website-mcp directory"]
    for path in sorted(workspace.rglob("*")):
        if path.is_symlink():
            errors.append(f"{path.relative_to(workspace)}: symlink is not permitted")
            continue
        if not path.is_file():
            continue
        relative = str(path.relative_to(workspace))
        raw = path.read_bytes()
        if len(raw) > MAX_SCAN_BYTES:
            errors.append(f"{relative}: exceeds {MAX_SCAN_BYTES}-byte scan policy")
            continue
        if b"\x00" in raw:
            errors.append(f"{relative}: binary content requires explicit handling")
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"{relative}: binary content requires explicit handling")
            continue
        if path.suffix.lower() in {".json", ".har"}:
            try:
                _scan_json(json.loads(text), (), errors, relative)
            except json.JSONDecodeError:
                errors.append(f"{relative}: malformed JSON evidence")
        elif path.suffix.lower() == ".jsonl":
            for line_number, line in enumerate(text.splitlines(), 1):
                if not line.strip():
                    continue
                try:
                    _scan_json(json.loads(line), (str(line_number),), errors, relative)
                except json.JSONDecodeError:
                    errors.append(f"{relative}:{line_number}: malformed JSONL record")
        for line_number, line in enumerate(text.splitlines(), 1):
            if any(pattern.search(line) for pattern in KNOWN_SECRET_PATTERNS):
                errors.append(f"{relative}:{line_number}: suspected secret pattern")
            if path.suffix.lower() not in {".json", ".jsonl", ".har"}:
                assignment = SENSITIVE_ASSIGNMENT.match(line)
                if assignment and not SAFE_ASSIGNMENT.fullmatch(assignment.group(2)):
                    errors.append(f"{relative}:{line_number}: sensitive-key assignment is not permitted")
                for match in IDENTIFIER_ASSIGNMENT.finditer(line):
                    key, candidate = match.group("key"), _identifier_value(match)
                    if candidate.startswith("${"):
                        continue
                    if is_sensitive_key(key) and candidate not in {"[REDACTED]", "<redacted>"}:
                        errors.append(
                            f"{relative}:{line_number}: sensitive identifier {key} is not permitted"
                        )
    return sorted(set(errors))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("project", type=Path)
    args = parser.parse_args()
    errors = scan_workspace(args.project.resolve() / ".website-mcp")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print("no contextual secret leaks detected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
