"""Validated direct HTTP adapter; no browser or shell fallback."""

from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import tempfile
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.parse import urlparse

from .auth import AuthSession


class HttpError(ValueError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def _check_schema(value: object, schema: object, label: str) -> None:
    if not isinstance(schema, dict):
        return
    kind = schema.get("type")
    if kind == "string" and not isinstance(value, str):
        raise HttpError(f"{label}_must_be_string")
    if kind == "integer" and (isinstance(value, bool) or not isinstance(value, int)):
        raise HttpError(f"{label}_must_be_integer")
    if kind == "number" and (isinstance(value, bool) or not isinstance(value, (int, float))):
        raise HttpError(f"{label}_must_be_number")
    if kind == "boolean" and not isinstance(value, bool):
        raise HttpError(f"{label}_must_be_boolean")
    if kind == "object":
        if not isinstance(value, dict):
            raise HttpError(f"{label}_must_be_object")
        required = schema.get("required", [])
        properties = schema.get("properties", {})
        if isinstance(required, list):
            for name in required:
                if isinstance(name, str) and name not in value:
                    raise HttpError(f"{label}_missing_required_{name}")
        if isinstance(properties, dict):
            if schema.get("additionalProperties") is False and set(value) - set(properties):
                raise HttpError(f"{label}_has_undeclared_property")
            for name, child in value.items():
                if name in properties:
                    _check_schema(child, properties[name], f"{label}_{name}")
    if kind == "array":
        if not isinstance(value, list):
            raise HttpError(f"{label}_must_be_array")
        maximum_items = schema.get("maxItems")
        if isinstance(maximum_items, int) and len(value) > maximum_items:
            raise HttpError(f"{label}_exceeds_max_items")
        item_schema = schema.get("items")
        for index, item in enumerate(value):
            _check_schema(item, item_schema, f"{label}_{index}")
    enum = schema.get("enum")
    if isinstance(enum, list) and value not in enum:
        raise HttpError(f"{label}_is_not_allowed")
    maximum = schema.get("maximum")
    if isinstance(maximum, (int, float)) and isinstance(value, (int, float)) and value > maximum:
        raise HttpError(f"{label}_exceeds_contract_maximum")


def _supported_json_schema(schema: object) -> bool:
    if not isinstance(schema, dict) or schema.get("type") not in {"object", "array", "string", "integer", "number", "boolean"}:
        return False
    if any(key in schema for key in ("$ref", "oneOf", "anyOf", "allOf", "not")):
        return False
    properties = schema.get("properties", {})
    if schema.get("type") == "object":
        return isinstance(properties, dict) and all(_supported_json_schema(item) for item in properties.values())
    if schema.get("type") == "array":
        return _supported_json_schema(schema.get("items"))
    return True


def _safe_root(reference: object, label: str) -> Path:
    if not isinstance(reference, str) or not reference.startswith("env:"):
        raise HttpError(f"{label}_root_is_not_configured")
    try:
        source = Path(os.environ[reference[4:]]).expanduser()
        if source.is_symlink():
            raise OSError("symlink")
        root = source.resolve(strict=True)
    except (KeyError, OSError) as exc:
        raise HttpError(f"{label}_root_is_not_configured") from exc
    if not root.is_dir():
        raise HttpError(f"{label}_root_is_not_configured")
    return root


def _safe_io_path(value: object, root: Path, label: str, *, existing: bool) -> Path:
    if not isinstance(value, str) or not value:
        raise HttpError(f"{label}_path_is_required")
    raw = Path(value)
    if raw.is_absolute() or ".." in raw.parts:
        raise HttpError(f"{label}_path_outside_root")
    path = root / raw
    cursor = root
    for part in raw.parts[:-1]:
        cursor = cursor / part
        if cursor.is_symlink() or not cursor.is_dir():
            raise HttpError(f"{label}_path_is_unsafe")
    if path.is_symlink() or (not existing and path.exists()):
        raise HttpError(f"{label}_path_is_unsafe")
    try:
        path.parent.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as exc:
        raise HttpError(f"{label}_path_outside_root") from exc
    if existing and (not path.is_file() or path.is_symlink()):
        raise HttpError(f"{label}_path_is_unsafe")
    return path


def _multipart(path: Path) -> tuple[bytes, str]:
    if not path.is_file() or path.is_symlink():
        raise HttpError("upload_path_is_not_a_regular_file")
    boundary = "----website-mcp-boundary"
    content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    body = b"".join(
        [
            f"--{boundary}\r\n".encode(),
            f'Content-Disposition: form-data; name="file"; filename="{path.name}"\r\n'.encode(),
            f"Content-Type: {content_type}\r\n\r\n".encode(),
            path.read_bytes(),
            f"\r\n--{boundary}--\r\n".encode(),
        ]
    )
    return body, f"multipart/form-data; boundary={boundary}"


class HttpAdapter:
    def __init__(self, config: dict[str, Any]) -> None:
        self.base_url = str(config["base_url"]).rstrip("/")
        self.operations = config.get("operations", {})
        self.max_limit = int(config.get("limits", {}).get("max_limit", 100))
        self.max_download_bytes = int(config.get("limits", {}).get("max_download_bytes", 25 * 1024 * 1024))
        self.io = config.get("io", {}) if isinstance(config.get("io"), dict) else {}
        self.auth = AuthSession(config.get("auth", {}), self.base_url)
        parsed = urlparse(self.base_url)
        self.origin = (parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port or (443 if parsed.scheme.lower() == "https" else 80))
        self.opener = build_opener(_NoRedirect())

    def call(self, operation_id: str, arguments: object, auth_modes: object, side_effect: object) -> Any:
        operation = self.operations.get(operation_id)
        if not isinstance(operation, dict):
            raise HttpError("unknown_operation")
        if not isinstance(arguments, dict):
            raise HttpError("arguments_must_be_object")
        return self._request(operation, arguments, auth_modes, str(side_effect), retry=False)

    def _request(self, operation: dict[str, Any], arguments: dict[str, Any], auth_modes: object, side_effect: str, retry: bool) -> Any:
        declared = [item for item in operation.get("parameters", []) if isinstance(item, dict)]
        operation_type = operation.get("type")
        if "body" in arguments and not isinstance(operation.get("request_body"), dict):
            raise HttpError("request_body_not_permitted")
        if "upload_path" in arguments and operation_type != "upload":
            raise HttpError("upload_not_permitted")
        if "download_path" in arguments and operation_type != "download":
            raise HttpError("download_not_permitted")
        if operation_type == "download" and "download_path" not in arguments:
            raise HttpError("download_path_is_required")
        names = {item.get("name") for item in declared if isinstance(item.get("name"), str)}
        special = {"body", "upload_path", "download_path"}
        unexpected = set(arguments) - names - special
        if unexpected:
            raise HttpError("arguments_not_in_contract")
        path = str(operation["path"])
        query: list[tuple[str, str]] = []
        headers = self.auth.headers(auth_modes)
        for parameter in declared:
            name = parameter.get("name")
            location = parameter.get("in")
            if not isinstance(name, str) or location not in {"path", "query", "header"}:
                continue
            if name not in arguments:
                if parameter.get("required") is True:
                    raise HttpError(f"missing_required_{name}")
                continue
            value = arguments[name]
            _check_schema(value, parameter.get("schema"), name)
            if name == "limit" and isinstance(value, int):
                value = min(value, self.max_limit)
            if location == "path":
                path = path.replace("{" + name + "}", quote(str(value), safe=""))
            elif location == "query":
                query.append((name, str(value).lower() if isinstance(value, bool) else str(value)))
            else:
                headers[name] = str(value)
        url = self.base_url + path + (("?" + urlencode(query)) if query else "")
        parsed_url = urlparse(url)
        actual_origin = (parsed_url.scheme.lower(), (parsed_url.hostname or "").lower(), parsed_url.port or (443 if parsed_url.scheme.lower() == "https" else 80))
        if actual_origin != self.origin:
            raise HttpError("cross_origin_request_not_allowed")
        data: bytes | None = None
        if "upload_path" in arguments:
            upload_root = _safe_root(self.io.get("upload_root_ref"), "upload")
            upload = _safe_io_path(arguments["upload_path"], upload_root, "upload", existing=True)
            content = operation.get("request_body", {}).get("content", {}) if isinstance(operation.get("request_body"), dict) else {}
            if isinstance(content, dict) and "text/csv" in content:
                data, content_type = upload.read_bytes(), "text/csv"
            else:
                data, content_type = _multipart(upload)
            headers["Content-Type"] = content_type
        elif "body" in arguments:
            content = operation["request_body"].get("content")
            json_media = content.get("application/json") if isinstance(content, dict) else None
            schema = json_media.get("schema") if isinstance(json_media, dict) else None
            if json_media is None:
                raise HttpError("request_body_json_not_declared")
            if not _supported_json_schema(schema):
                raise HttpError("request_body_schema_not_supported")
            _check_schema(arguments["body"], schema, "body")
            data = json.dumps(arguments["body"], separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"
        try:
            with self.opener.open(Request(url, data=data, method=str(operation["method"]), headers=headers), timeout=15) as response:
                raw = self._bounded_read(response)
                content_type = response.headers.get("Content-Type", "")
        except HTTPError as exc:
            if 300 <= exc.code < 400:
                raise HttpError("redirect_not_allowed") from exc
            if exc.code == 401 and not retry and side_effect in {"none", "read"} and self.auth.reauthenticate(auth_modes):
                return self._request(operation, arguments, auth_modes, side_effect, retry=True)
            exc.read(4096)
            raise HttpError(f"http_{exc.code}_upstream_error") from exc
        if operation_type == "download":
            download_root = _safe_root(self.io.get("download_root_ref"), "download")
            destination = _safe_io_path(arguments.get("download_path"), download_root, "download", existing=False)
            self._write_exclusive(destination, raw)
            return {"path": str(destination), "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        if "json" in content_type.lower():
            try:
                return json.loads(raw)
            except json.JSONDecodeError as exc:
                raise HttpError("response_json_is_invalid") from exc
        return {"text": raw.decode("utf-8", errors="replace"), "bytes": len(raw)}

    def _bounded_read(self, response: Any) -> bytes:
        chunks: list[bytes] = []
        remaining = self.max_download_bytes
        while True:
            chunk = response.read(min(65536, remaining + 1))
            if not chunk:
                break
            remaining -= len(chunk)
            if remaining < 0:
                raise HttpError("response_exceeds_byte_limit")
            chunks.append(chunk)
        return b"".join(chunks)

    @staticmethod
    def _write_exclusive(path: Path, raw: bytes) -> None:
        descriptor, temporary_name = tempfile.mkstemp(prefix=".website-mcp-download.", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary, path)
        except FileExistsError as exc:
            raise HttpError("download_path_already_exists") from exc
        finally:
            temporary.unlink(missing_ok=True)
