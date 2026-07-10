#!/usr/bin/env python3
import argparse
import csv
import io
import json
import os
import secrets
import threading
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


LOCK = threading.RLock()
STATE: dict[str, object] = {}


def reset() -> None:
    with LOCK:
        STATE.clear()
        STATE.update(
            items={"i-1": {"id": "i-1", "name": "Starter", "quantity": 1, "version": 1}},
            sessions={}, imports={}, idempotency={}, next_item=2, next_session=1,
            next_import=1, rate_limit=0,
        )


def operation(route: str, kind: str, operation_id: str, *, public: bool = False, path_id: str | None = None) -> dict:
    value = {
        "operationId": operation_id,
        "security": [] if public else [{"cookieSession": []}],
        "responses": {"200": {"description": "Successful fixture response"}},
        "x-mcp": {"route": route, "type": kind, "surface": "hybrid"},
    }
    if path_id:
        value["parameters"] = [
            {"name": path_id, "in": "path", "required": True, "schema": {"type": "string"}}
        ]
    return value


def openapi() -> dict:
    return {
        "openapi": "3.1.0",
        "info": {"title": "Session admin fixture", "version": "1.0.0"},
        "components": {"securitySchemes": {"cookieSession": {"type": "apiKey", "in": "cookie", "name": "fixture_session"}}},
        "paths": {
            "/session": {
                "post": operation("/session", "auth", "session.login", public=True),
                "delete": operation("/session", "auth", "session.logout"),
            },
            "/api/session": {"get": operation("/api/session", "auth", "session.get")},
            "/api/items": {
                "get": operation("/api/items", "read", "items.list"),
                "post": operation("/api/items", "create", "items.create"),
            },
            "/api/items/{id}": {
                "get": operation("/api/items/{id}", "read", "items.get", path_id="id"),
                "patch": operation("/api/items/{id}", "update", "items.update", path_id="id"),
                "delete": operation("/api/items/{id}", "delete", "items.delete", path_id="id"),
            },
            "/api/items/batch": {"post": operation("/api/items/batch", "action", "items.batch")},
            "/api/imports": {"post": operation("/api/imports", "upload", "imports.preview")},
            "/api/imports/{id}/commit": {"post": operation("/api/imports/{id}/commit", "action", "imports.commit", path_id="id")},
            "/api/imports/{id}/errors.csv": {"get": operation("/api/imports/{id}/errors.csv", "download", "imports.errors", path_id="id")},
            "/api/exports/items.csv": {"get": operation("/api/exports/items.csv", "download", "items.export")},
        },
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "SessionAdminFixture/1"

    def log_message(self, format: str, *args: object) -> None:
        return

    def read_body(self) -> bytes:
        return self.rfile.read(int(self.headers.get("Content-Length", "0")))

    def read_json(self) -> object:
        raw = self.read_body()
        return json.loads(raw) if raw else None

    def send_bytes(self, status: int, body: bytes, content_type: str, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status: int, value: object, headers: dict[str, str] | None = None) -> None:
        self.send_bytes(status, json.dumps(value, separators=(",", ":")).encode(), "application/json", headers)

    def session(self) -> tuple[str, dict] | None:
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get("fixture_session")
        if not morsel:
            return None
        with LOCK:
            value = STATE["sessions"].get(morsel.value)
            return (morsel.value, value) if value else None

    def require_auth(self, *, csrf: bool = False) -> tuple[str, dict] | None:
        current = self.session()
        if current is None:
            self.send_json(401, {"error": "auth_required"})
            return None
        if csrf and self.headers.get("X-CSRF-Token") != current[1]["csrf"]:
            self.send_json(403, {"error": "csrf_invalid"})
            return None
        return current

    def rate_limited(self, path: str) -> bool:
        if not path.startswith("/api/"):
            return False
        with LOCK:
            remaining = int(STATE["rate_limit"])
            if remaining <= 0:
                return False
            STATE["rate_limit"] = remaining - 1
        self.send_json(429, {"error": "rate_limited"}, {"Retry-After": "1"})
        return True

    def control_authorized(self) -> bool:
        supplied = self.headers.get("X-Fixture-Control", "")
        expected = self.server.control_token
        if not supplied or not secrets.compare_digest(supplied, expected):
            self.send_json(403, {"error": "fixture_control_forbidden"})
            return False
        return True

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/openapi.json":
            self.send_json(200, openapi())
            return
        if path == "/login":
            self.send_bytes(200, b'<form action="/session" method="post"><input name="username"><input name="password" type="password"></form>', "text/html")
            return
        if self.rate_limited(path):
            return
        if path == "/admin":
            current = self.require_auth()
            if current:
                self.send_bytes(200, f'<meta name="csrf" content="{current[1]["csrf"]}"><script src="/admin.js"></script>'.encode(), "text/html")
            return
        if path == "/admin.js":
            self.send_bytes(200, b'fetch("/api/items");', "application/javascript")
            return
        if path == "/api/session":
            current = self.require_auth()
            if current:
                self.send_json(200, {"authenticated": True, "csrf": current[1]["csrf"]})
            return
        if path == "/api/items":
            if not self.require_auth():
                return
            query = parse_qs(parsed.query)
            try:
                start = int(query.get("cursor", ["0"])[0])
                limit = max(1, min(50, int(query.get("limit", ["20"])[0])))
            except ValueError:
                self.send_json(400, {"error": "invalid_cursor_or_limit"})
                return
            with LOCK:
                items = [dict(item) for item in STATE["items"].values()]
            page = items[start:start + limit]
            self.send_json(200, {"items": page, "next_cursor": str(start + limit) if start + limit < len(items) else None})
            return
        if path.startswith("/api/items/"):
            if not self.require_auth():
                return
            item_id = path.rsplit("/", 1)[-1]
            with LOCK:
                item = STATE["items"].get(item_id)
            if item:
                self.send_json(200, item, {"ETag": f'"{item["version"]}"'})
            else:
                self.send_json(404, {"error": "not_found"})
            return
        if path.startswith("/api/imports/") and path.endswith("/errors.csv"):
            if not self.require_auth():
                return
            import_id = path.split("/")[3]
            with LOCK:
                record = STATE["imports"].get(import_id)
            if record is None:
                self.send_json(404, {"error": "not_found"})
                return
            output = io.StringIO()
            writer = csv.writer(output, lineterminator="\n")
            writer.writerow(["row", "error"])
            for error in record["errors"]:
                writer.writerow([error["row"], error["error"]])
            self.send_bytes(200, output.getvalue().encode(), "text/csv")
            return
        if path == "/api/exports/items.csv":
            if not self.require_auth():
                return
            output = io.StringIO()
            writer = csv.writer(output, lineterminator="\n")
            writer.writerow(["id", "name", "quantity"])
            with LOCK:
                for item in STATE["items"].values():
                    writer.writerow([item["id"], item["name"], item["quantity"]])
            self.send_bytes(200, output.getvalue().encode(), "text/csv")
            return
        self.send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/__fixture/reset":
            if self.control_authorized():
                reset()
                self.send_json(200, {"reset": True})
            return
        if path == "/__fixture/expire-session":
            if self.control_authorized():
                with LOCK:
                    STATE["sessions"].clear()
                self.send_json(200, {"expired": True})
            return
        if path == "/__fixture/rate-limit-next":
            if self.control_authorized():
                with LOCK:
                    STATE["rate_limit"] = 1
                self.send_json(200, {"count": 1})
            return
        if path == "/session":
            try:
                credentials = self.read_json()
            except json.JSONDecodeError:
                self.send_json(400, {"error": "invalid_json"})
                return
            configured_user = os.environ.get("FIXTURE_ADMIN_USER")
            configured_password = os.environ.get("FIXTURE_ADMIN_PASSWORD")
            if not configured_user or not configured_password:
                self.send_json(401, {"error": "auth_not_configured"})
                return
            if not isinstance(credentials, dict) or credentials.get("username") != configured_user or credentials.get("password") != configured_password:
                self.send_json(401, {"error": "invalid_credentials"})
                return
            with LOCK:
                number = STATE["next_session"]
                STATE["next_session"] = number + 1
                session_id, csrf_token = f"s-{number}", f"csrf-{number}"
                STATE["sessions"][session_id] = {"csrf": csrf_token}
            self.send_json(200, {"authenticated": True, "csrf": csrf_token}, {"Set-Cookie": f"fixture_session={session_id}; HttpOnly; SameSite=Strict; Path=/"})
            return
        if self.rate_limited(path):
            return
        if path == "/api/items":
            if not self.require_auth(csrf=True):
                return
            key = self.headers.get("Idempotency-Key")
            if not key:
                self.send_json(400, {"error": "idempotency_key_required"})
                return
            try:
                value = self.read_json()
            except json.JSONDecodeError:
                self.send_json(400, {"error": "invalid_json"})
                return
            if not isinstance(value, dict) or not isinstance(value.get("name"), str) or not isinstance(value.get("quantity"), int):
                self.send_json(422, {"error": "invalid_item"})
                return
            with LOCK:
                prior = STATE["idempotency"].get(key)
                if prior:
                    item = dict(prior)
                    status = 200
                else:
                    number = STATE["next_item"]
                    STATE["next_item"] = number + 1
                    item = {"id": f"i-{number}", "name": value["name"], "quantity": value["quantity"], "version": 1}
                    STATE["items"][item["id"]] = item
                    STATE["idempotency"][key] = dict(item)
                    status = 201
            self.send_json(status, item, {"ETag": f'"{item["version"]}"'})
            return
        if path == "/api/items/batch":
            if not self.require_auth(csrf=True):
                return
            try:
                operations = self.read_json()
            except json.JSONDecodeError:
                operations = None
            if not isinstance(operations, list) or len(operations) > 20:
                self.send_json(400, {"error": "batch_limit", "maximum": 20})
                return
            results = []
            with LOCK:
                for operation_value in operations:
                    item = STATE["items"].get(operation_value.get("id")) if isinstance(operation_value, dict) else None
                    if item is None or not isinstance(operation_value.get("quantity"), int):
                        results.append({"id": operation_value.get("id") if isinstance(operation_value, dict) else None, "status": 404})
                    else:
                        item["quantity"] = operation_value["quantity"]
                        item["version"] += 1
                        results.append({"id": item["id"], "status": 200})
            code = 207 if any(result["status"] != 200 for result in results) else 200
            self.send_json(code, {"results": results})
            return
        if path == "/api/imports":
            if not self.require_auth(csrf=True):
                return
            try:
                rows = list(csv.DictReader(io.StringIO(self.read_body().decode("utf-8"))))
            except (UnicodeDecodeError, csv.Error):
                self.send_json(400, {"error": "invalid_csv"})
                return
            valid, errors = [], []
            for row_number, row in enumerate(rows, 2):
                try:
                    quantity = int(row.get("quantity", ""))
                    if not row.get("name"):
                        raise ValueError
                    valid.append({"name": row["name"], "quantity": quantity})
                except ValueError:
                    errors.append({"row": row_number, "error": "invalid quantity or name"})
            with LOCK:
                number = STATE["next_import"]
                STATE["next_import"] = number + 1
                import_id = f"imp-{number}"
                STATE["imports"][import_id] = {"rows": valid, "errors": errors, "committed": False}
            self.send_json(200, {"import_id": import_id, "valid_count": len(valid), "error_count": len(errors)})
            return
        if path.startswith("/api/imports/") and path.endswith("/commit"):
            if not self.require_auth(csrf=True):
                return
            import_id = path.split("/")[3]
            with LOCK:
                record = STATE["imports"].get(import_id)
                if record is None:
                    self.send_json(404, {"error": "not_found"})
                    return
                if record["errors"]:
                    self.send_json(409, {"error": "validation_failed", "error_count": len(record["errors"])})
                    return
                if record["committed"]:
                    self.send_json(200, {"import_id": import_id, "committed": True, "replayed": True})
                    return
                for row in record["rows"]:
                    number = STATE["next_item"]
                    STATE["next_item"] = number + 1
                    STATE["items"][f"i-{number}"] = {"id": f"i-{number}", **row, "version": 1}
                record["committed"] = True
            self.send_json(200, {"import_id": import_id, "committed": True})
            return
        self.send_json(404, {"error": "not_found"})

    def do_PATCH(self) -> None:
        path = urlparse(self.path).path
        if not path.startswith("/api/items/") or not self.require_auth(csrf=True):
            if not path.startswith("/api/items/"):
                self.send_json(404, {"error": "not_found"})
            return
        item_id = path.rsplit("/", 1)[-1]
        with LOCK:
            item = STATE["items"].get(item_id)
            if item is None:
                self.send_json(404, {"error": "not_found"})
                return
            if self.headers.get("If-Match") != f'"{item["version"]}"':
                self.send_json(412, {"error": "etag_conflict"})
                return
            try:
                changes = self.read_json()
            except json.JSONDecodeError:
                changes = None
            if not isinstance(changes, dict) or any(key not in {"name", "quantity"} for key in changes):
                self.send_json(422, {"error": "invalid_patch"})
                return
            item.update(changes)
            item["version"] += 1
            result = dict(item)
        self.send_json(200, result, {"ETag": f'"{result["version"]}"'})

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        if not self.require_auth(csrf=True):
            return
        if path == "/session":
            current = self.session()
            with LOCK:
                if current:
                    STATE["sessions"].pop(current[0], None)
            self.send_json(200, {"logged_out": True})
        elif path.startswith("/api/items/"):
            item_id = path.rsplit("/", 1)[-1]
            with LOCK:
                removed = STATE["items"].pop(item_id, None)
            self.send_json(200 if removed else 404, {"deleted": bool(removed)})
        else:
            self.send_json(404, {"error": "not_found"})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    reset()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.control_token = secrets.token_urlsafe(24)
    print(json.dumps({"host": "127.0.0.1", "port": server.server_port, "control_token": server.control_token}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
