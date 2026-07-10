#!/usr/bin/env python3
import argparse
import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


PROJECTS = {
    "p-1": {"id": "p-1", "name": "Project One", "updated_at": "2026-07-09T10:00:00Z"},
    "p-2": {"id": "p-2", "name": "Project Two", "updated_at": "2026-07-09T11:00:00Z"},
}
EVENTS = {
    "p-1": [
        {"id": "e-1", "kind": "created", "at": "2026-07-09T10:00:00Z"},
        {"id": "e-2", "kind": "updated", "at": "2026-07-09T12:00:00Z"},
    ],
    "p-2": [{"id": "e-3", "kind": "created", "at": "2026-07-09T11:00:00Z"}],
}
ASSETS = {("p-1", "brief.txt"): b"Project One brief\n", ("p-2", "brief.txt"): b"Project Two brief\n"}


def operation(route: str, kind: str, operation_id: str, path_parameters: list[str] | None = None) -> dict:
    value = {
        "operationId": operation_id,
        "security": [],
        "responses": {"200": {"description": "Successful fixture response"}},
        "x-mcp": {"route": route, "type": kind, "surface": "hybrid"},
    }
    if path_parameters:
        value["parameters"] = [
            {"name": name, "in": "path", "required": True, "schema": {"type": "string"}}
            for name in path_parameters
        ]
    return value


def partial_openapi() -> dict:
    return {
        "openapi": "3.1.0",
        "info": {"title": "Hybrid project fixture (partial)", "version": "1.0.0"},
        "paths": {
            "/api/projects": {"get": operation("/api/projects", "read", "projects.list")},
            "/api/projects/{id}": {
                "get": operation("/api/projects/{id}", "read", "projects.get", ["id"])
            },
            "/api/projects/{id}/assets/{name}": {
                "get": operation(
                    "/api/projects/{id}/assets/{name}", "download", "projects.asset", ["id", "name"]
                )
            },
        },
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "HybridCliFixture/1"

    def log_message(self, format: str, *args: object) -> None:
        return

    def send_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status: int, value: object) -> None:
        self.send_bytes(status, json.dumps(value, separators=(",", ":")).encode(), "application/json")

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path, query = parsed.path, parse_qs(parsed.query)
        if path == "/":
            links = "".join(f'<li><a href="/projects/{item["id"]}">{item["name"]}</a></li>' for item in PROJECTS.values())
            self.send_bytes(200, f'<!doctype html><link rel="service-desc" href="/.well-known/openapi.json"><ul>{links}</ul><script src="/static/project.js"></script>'.encode(), "text/html")
        elif path.startswith("/projects/"):
            project_id = path.rsplit("/", 1)[-1]
            project = PROJECTS.get(project_id)
            if project:
                self.send_bytes(200, f'<main data-project-id="{project_id}">{project["name"]}</main><script src="/static/project.js"></script>'.encode(), "text/html")
            else:
                self.send_json(404, {"error": "not_found"})
        elif path == "/static/project.js":
            script = b'''const id=document.querySelector("[data-project-id]")?.dataset.projectId||"p-1";fetch(`/api/projects/${id}/events?limit=20`).then(r=>r.json());'''
            self.send_bytes(200, script, "application/javascript")
        elif path == "/.well-known/openapi.json":
            self.send_json(200, partial_openapi())
        elif path == "/api/projects":
            self.send_json(200, {"items": list(PROJECTS.values())})
        elif path.startswith("/api/projects/"):
            parts = path.strip("/").split("/")
            project_id = parts[2] if len(parts) >= 3 else ""
            project = PROJECTS.get(project_id)
            if project is None:
                self.send_json(404, {"error": "not_found"})
            elif len(parts) == 3:
                self.send_json(200, project)
            elif len(parts) == 4 and parts[3] == "events":
                try:
                    start = int(query.get("cursor", ["0"])[0])
                    limit = max(1, min(50, int(query.get("limit", ["20"])[0])))
                except ValueError:
                    self.send_json(400, {"error": "invalid_cursor_or_limit"})
                    return
                events = EVENTS[project_id]
                self.send_json(200, {"items": events[start:start + limit], "next_cursor": str(start + limit) if start + limit < len(events) else None})
            elif len(parts) == 5 and parts[3] == "assets":
                asset = ASSETS.get((project_id, parts[4]))
                if asset is None:
                    self.send_json(404, {"error": "not_found"})
                else:
                    self.send_bytes(200, asset, "text/plain")
            else:
                self.send_json(404, {"error": "not_found"})
        else:
            self.send_json(404, {"error": "not_found"})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.control_token = secrets.token_urlsafe(24)
    print(json.dumps({"host": "127.0.0.1", "port": server.server_port, "control_token": server.control_token}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
