"""References-only auth injection and bounded read reauthentication."""

from __future__ import annotations

import json
import os
import re
from http.cookies import SimpleCookie
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


class AuthError(ValueError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def _env_ref(reference: object) -> str:
    if not isinstance(reference, str) or not reference.startswith("env:"):
        raise AuthError("auth_secret_reference_must_be_env")
    name = reference[4:]
    if not name or any(not (char.isupper() or char.isdigit() or char == "_") for char in name):
        raise AuthError("invalid_auth_environment_reference")
    value = os.environ.get(name)
    if not value:
        raise AuthError("configured_auth_environment_is_missing")
    return value


class AuthSession:
    def __init__(self, config: dict[str, Any], base_url: str) -> None:
        self.modes = [item for item in config.get("modes", []) if isinstance(item, dict)]
        self.base_url = base_url.rstrip("/") + "/"
        parsed = urlparse(self.base_url)
        self.origin = (parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port or (443 if parsed.scheme.lower() == "https" else 80))
        self.opener = build_opener(_NoRedirect())
        self._cookies: dict[str, str] = {}
        self._csrf: dict[str, str] = {}

    def headers(self, mode_ids: object) -> dict[str, str]:
        output: dict[str, str] = {"Accept": "application/json, */*;q=0.8"}
        ids = mode_ids if isinstance(mode_ids, list) else []
        for mode_id in ids:
            mode = next((item for item in self.modes if item.get("id") == mode_id), None)
            if mode is None or mode.get("kind") == "anonymous":
                continue
            value = _env_ref(mode.get("secret_ref"))
            kind = mode.get("kind")
            injection = str(mode.get("injection", "")).lower()
            if kind in {"bearer", "oauth"} or "bearer" in injection:
                output[mode.get("header_name", "Authorization")] = f"Bearer {value}"
            elif kind == "cookie-session" or "cookie" in injection:
                cookie_header = mode.get("header_name", "Cookie")
                output[cookie_header] = self._cookies.get(str(mode_id), value)
                csrf_ref = mode.get("csrf_ref")
                csrf_header = mode.get("csrf_header")
                if isinstance(csrf_ref, str) and isinstance(csrf_header, str):
                    output[csrf_header] = self._csrf.get(str(mode_id), _env_ref(csrf_ref))
            else:
                header = mode.get("header_name")
                if not isinstance(header, str) or not header:
                    match = re.fullmatch(r"\s*([A-Za-z0-9-]+)\s+header\s*", str(mode.get("injection", "")), re.IGNORECASE)
                    header = match.group(1) if match else None
                if not isinstance(header, str) or not header:
                    raise AuthError("api_key_auth_requires_header_name")
                output[header] = value
        return output

    def reauthenticate(self, mode_ids: object) -> bool:
        """Perform at most one documented auth refresh; never guess an auth flow."""
        ids = mode_ids if isinstance(mode_ids, list) else []
        for mode_id in ids:
            mode = next((item for item in self.modes if item.get("id") == mode_id), None)
            if not isinstance(mode, dict):
                continue
            reauth = mode.get("reauth")
            if not isinstance(reauth, dict):
                continue
            path = reauth.get("path")
            if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
                continue
            method = str(reauth.get("method", "POST")).upper()
            if method not in {"POST", "PUT"}:
                continue
            body_ref = reauth.get("body_env_ref")
            try:
                body = _env_ref(body_ref).encode() if body_ref else None
            except AuthError:
                return False
            headers = {"Content-Type": "application/json"} if body else {}
            target = urljoin(self.base_url, path.lstrip("/"))
            parsed_target = urlparse(target)
            target_origin = (parsed_target.scheme.lower(), (parsed_target.hostname or "").lower(), parsed_target.port or (443 if parsed_target.scheme.lower() == "https" else 80))
            if target_origin != self.origin:
                continue
            try:
                with self.opener.open(Request(target, data=body, method=method, headers=headers), timeout=10) as response:
                    raw = response.read()
                    cookie = response.headers.get("Set-Cookie")
            except (HTTPError, OSError):
                return False
            if cookie:
                parsed = SimpleCookie(cookie)
                self._cookies[str(mode_id)] = "; ".join(f"{key}={morsel.value}" for key, morsel in parsed.items())
            csrf_field = reauth.get("csrf_response_field")
            if isinstance(csrf_field, str):
                try:
                    value = json.loads(raw).get(csrf_field)
                except (json.JSONDecodeError, AttributeError):
                    value = None
                if isinstance(value, str):
                    self._csrf[str(mode_id)] = value
            return bool(cookie or self._csrf.get(str(mode_id)))
        return False
