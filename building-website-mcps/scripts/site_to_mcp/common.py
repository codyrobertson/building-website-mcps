from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

try:
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - Windows fallback below
    _fcntl = None
try:
    import msvcrt as _msvcrt
except ImportError:  # pragma: no cover - POSIX fallback above
    _msvcrt = None


SECRET_TEXT = [
    re.compile(r"(?i)((?:authorization|x-api-key|api[_-]?key|bearer|token)\s*[:=]\s*)([^\s,;]+)"),
    re.compile(r"(?i)((?:set-)?cookie\s*[:=]\s*)([^\r\n]+)"),
    re.compile(r"(?i)([?&](?:access[_-]?token|refresh[_-]?token|token|api[_-]?key|password|secret)=)([^&#\s]+)"),
    re.compile(r"(?i)(https?://)(?:[^/\s@]+)@"),
]
IDENTIFIER_ASSIGNMENT = re.compile(
    r"(?P<prefix>\b(?P<key>[A-Za-z_$][A-Za-z0-9_$-]*)\s*[:=]\s*)"
    r"(?:"
    r'"(?P<double_value>(?:\\.|[^"\\])*)"'
    r"|'(?P<single_value>(?:\\.|[^'\\])*)'"
    r"|(?P<bare_value>[^\s;<>\"']+)"
    r")"
)
SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "setcookie",
    "password",
    "passwd",
    "token",
    "accesstoken",
    "refreshtoken",
    "sessionid",
    "apikey",
    "clientsecret",
    "privatekey",
    "secret",
    "xapikey",
    "bearer",
}
SENSITIVE_KEY_STEMS = {
    "apikey",
    "authorization",
    "bearer",
    "clientsecret",
    "cookie",
    "credential",
    "password",
    "privatekey",
    "refreshtoken",
    "secret",
    "session",
    "sessionid",
    "token",
}
SAFE_SENSITIVE_METADATA_KEYS = {"secretpolicy"}
QUERY_PAIR = re.compile(r"([?&])([^=&\s]+)=([^&#\s]+)")


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def fresh_until(hours: int = 24) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat().replace(
        "+00:00", "Z"
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def write_json_atomic(path: Path, value: object) -> None:
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


def write_bytes_atomic(path: Path, value: bytes) -> None:
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def ensure_workspace_safe(workspace: Path) -> None:
    if workspace.is_symlink():
        raise ValueError("workspace path is a symlink")
    if not workspace.is_dir():
        raise ValueError("missing .website-mcp directory")
    for path in workspace.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"workspace contains a symlink: {path.relative_to(workspace)}")


def is_sensitive_key(key: str) -> bool:
    if key.startswith("/"):
        return False
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    if not normalized:
        return False
    if normalized in SAFE_SENSITIVE_METADATA_KEYS:
        return False
    if normalized.endswith("ref") and any(
        normalized == f"{stem}ref" for stem in SENSITIVE_KEY_STEMS
    ):
        return False
    if normalized in SENSITIVE_KEYS:
        return True
    if "_" not in key and "-" not in key:
        return False
    return any(
        normalized.startswith(stem) or normalized.endswith(stem)
        for stem in SENSITIVE_KEY_STEMS
    )


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
    raise RuntimeError("no supported file-lock backend")


def _unlock_file(handle: Any) -> None:
    if _fcntl is not None:
        _fcntl.flock(handle.fileno(), _fcntl.LOCK_UN)
    elif _msvcrt is not None:  # pragma: no cover - Windows
        handle.seek(0)
        _msvcrt.locking(handle.fileno(), _msvcrt.LK_UNLCK, 1)


@contextmanager
def _jsonl_lock(path: Path):
    if path.is_symlink():
        raise ValueError("JSONL path is a symlink")
    lock_path = path.with_name(f".{path.name}.lock")
    if lock_path.is_symlink():
        raise ValueError("JSONL lock path is a symlink")
    descriptor = os.open(
        lock_path,
        os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(descriptor, "a+", encoding="utf-8") as handle:
        _lock_file(handle)
        try:
            yield
        finally:
            _unlock_file(handle)


def _append_jsonl_unlocked(path: Path, value: dict[str, Any]) -> None:
    line = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
    descriptor = os.open(
        path,
        os.O_CREAT | os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ValueError("JSONL path must be a regular file")
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())


def append_jsonl(path: Path, value: dict[str, Any]) -> None:
    with _jsonl_lock(path):
        _append_jsonl_unlocked(path, value)


def append_jsonl_sequenced(path: Path, build_record: Any) -> dict[str, Any]:
    """Append exactly one ordered record while holding the JSONL writer lock."""
    with _jsonl_lock(path):
        records = read_jsonl(path)
        expected = list(range(1, len(records) + 1))
        if [record.get("seq") for record in records] != expected:
            raise ValueError(f"{path.name} sequence is invalid")
        record = build_record(len(records) + 1)
        if not isinstance(record, dict) or record.get("seq") != len(records) + 1:
            raise ValueError(f"{path.name} writer produced an invalid sequence")
        _append_jsonl_unlocked(path, record)
        return record


def append_jsonl_sequenced_many(path: Path, build_records: Any) -> list[dict[str, Any]]:
    """Append a contiguous ordered batch while holding one writer lock."""
    with _jsonl_lock(path):
        records = read_jsonl(path)
        expected = list(range(1, len(records) + 1))
        if [record.get("seq") for record in records] != expected:
            raise ValueError(f"{path.name} sequence is invalid")
        created: list[dict[str, Any]] = []
        for offset, build_record in enumerate(build_records, 1):
            record = build_record(len(records) + offset)
            if not isinstance(record, dict) or record.get("seq") != len(records) + offset:
                raise ValueError(f"{path.name} writer produced an invalid sequence")
            created.append(record)
        for record in created:
            _append_jsonl_unlocked(path, record)
        return created


def append_jsonl_sequenced_with_context(path: Path, build_record: Any) -> dict[str, Any]:
    return append_jsonl_sequenced_with_context_many(path, [build_record])[0]


def append_jsonl_sequenced_with_context_many(path: Path, build_records: Any) -> list[dict[str, Any]]:
    """Append ordered records whose builders receive the validated prior ledger."""
    with _jsonl_lock(path):
        records = read_jsonl(path)
        expected = list(range(1, len(records) + 1))
        if [record.get("seq") for record in records] != expected:
            raise ValueError(f"{path.name} sequence is invalid")
        staged = list(records)
        created: list[dict[str, Any]] = []
        for build_record in build_records:
            sequence = len(staged) + 1
            record = build_record(sequence, staged)
            if not isinstance(record, dict) or record.get("seq") != sequence:
                raise ValueError(f"{path.name} writer produced an invalid sequence")
            staged.append(record)
            created.append(record)
        for record in created:
            _append_jsonl_unlocked(path, record)
        return created


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if path.is_symlink():
        raise ValueError("JSONL path is a symlink")
    if not path.is_file():
        return []
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.strip():
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path.name}: malformed JSONL record {line_number}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"{path.name}: JSONL record {line_number} must be an object")
            records.append(value)
    return records


def redact_json_object(item: Any, redactions: list[str] | None = None) -> Any:
    found = redactions if redactions is not None else []
    if isinstance(item, dict):
        result: dict[str, Any] = {}
        for key, child in item.items():
            if is_sensitive_key(str(key)):
                result[key] = "[REDACTED]"
                found.append("json-secret")
            else:
                result[key] = redact_json_object(child, found)
        return result
    if isinstance(item, list):
        return [redact_json_object(child, found) for child in item]
    if isinstance(item, str):
        redacted, redactions = redact_text(item)
        found.extend(redactions)
        return redacted
    return item


def has_url_userinfo(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.username is not None or parsed.password is not None


def redact_url(value: str) -> tuple[str, list[str]]:
    parsed = urlparse(value)
    redactions: list[str] = []
    netloc = parsed.netloc
    if has_url_userinfo(value):
        host = parsed.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        try:
            port = parsed.port
        except ValueError:
            port = None
        netloc = "[REDACTED]@" + host + (f":{port}" if port is not None else "")
        redactions.append("url-userinfo")
    query: list[tuple[str, str]] = []
    for key, value_part in parse_qsl(parsed.query, keep_blank_values=True):
        if is_sensitive_key(key):
            query.append((key, "[REDACTED]"))
            redactions.append("url-query-secret")
        else:
            query.append((key, value_part))
    return urlunparse(parsed._replace(netloc=netloc, query=urlencode(query))), redactions


def redact_headers(headers: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    cleaned: dict[str, str] = {}
    redactions: list[str] = []
    for key, value in headers.items():
        sensitive = (
            is_sensitive_key(key)
            or bool(re.search(r"(?i)\b(?:bearer|basic)\s+\S+", value))
        )
        if sensitive:
            cleaned[key] = "[REDACTED]"
            redactions.append("header-secret")
        else:
            cleaned[key] = value
    return cleaned, redactions


def redact_text(text: str) -> tuple[str, list[str]]:
    redactions: list[str] = []
    value = text
    try:
        parsed = json.loads(text)
        value = json.dumps(redact_json_object(parsed, redactions), separators=(",", ":"))
    except json.JSONDecodeError:
        pass
    for index, pattern in enumerate(SECRET_TEXT):
        replacement = r"\1[REDACTED]" if index < 3 else r"\1[REDACTED]@"
        value, count = pattern.subn(replacement, value)
        if count:
            redactions.append(("header-secret", "cookie", "query-secret", "url-userinfo")[index])
    def redact_query(match: re.Match[str]) -> str:
        if is_sensitive_key(match.group(2)):
            redactions.append("query-secret")
            return f"{match.group(1)}{match.group(2)}=[REDACTED]"
        return match.group(0)

    value = QUERY_PAIR.sub(redact_query, value)
    def redact_identifier(match: re.Match[str]) -> str:
        if not is_sensitive_key(match.group("key")):
            return match.group(0)
        redactions.append("identifier-secret")
        if match.group("double_value") is not None:
            return f'{match.group("prefix")}"[REDACTED]"'
        if match.group("single_value") is not None:
            return f"{match.group('prefix')}'[REDACTED]'"
        return f"{match.group('prefix')}[REDACTED]"

    value = IDENTIFIER_ASSIGNMENT.sub(redact_identifier, value)
    return value, redactions


def same_origin(left: str, right: str) -> bool:
    try:
        a, b = urlparse(left), urlparse(right)
        return (
            not has_url_userinfo(left)
            and not has_url_userinfo(right)
            and a.scheme in {"http", "https"}
            and b.scheme in {"http", "https"}
            and a.scheme.lower() == b.scheme.lower()
            and a.hostname == b.hostname
            and (a.port or (443 if a.scheme == "https" else 80))
            == (b.port or (443 if b.scheme == "https" else 80))
        )
    except ValueError:
        return False


def safe_workspace_artifact(workspace: Path, relative: str) -> Path:
    ensure_workspace_safe(workspace)
    if not relative or Path(relative).is_absolute():
        raise ValueError("checkpoint artifact must be relative to .website-mcp")
    candidate = workspace / relative
    resolved = candidate.resolve(strict=True)
    resolved.relative_to(workspace.resolve())
    if candidate.is_symlink() or not resolved.is_file():
        raise ValueError("checkpoint artifact must be a regular workspace file")
    return resolved
