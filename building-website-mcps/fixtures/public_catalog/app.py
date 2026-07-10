#!/usr/bin/env python3
import argparse
import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


PRODUCTS = [
    {"id": "p-1", "name": "Red Mug", "price": 12.5, "category": "home", "tags": ["red"]},
    {"id": "p-2", "name": "Blue Rope", "price": 18.0, "category": "outdoor", "tags": ["blue"]},
    {"id": "p-3", "name": "Red Tent", "price": 79.0, "category": "outdoor", "tags": ["red"]},
]


def operation(route: str, kind: str, operation_id: str, parameters: list[dict] | None = None) -> dict:
    value = {
        "operationId": operation_id,
        "security": [],
        "responses": {"200": {"description": "Successful fixture response"}},
        "x-mcp": {"route": route, "type": kind, "surface": "hybrid"},
    }
    if parameters:
        value["parameters"] = parameters
    return value


def openapi() -> dict:
    product_parameter = {
        "name": "id", "in": "path", "required": True, "schema": {"type": "string"}
    }
    return {
        "openapi": "3.1.0",
        "info": {"title": "Public catalog fixture", "version": "1.0.0"},
        "paths": {
            "/api/categories": {"get": operation("/api/categories", "read", "categories.list")},
            "/api/products": {"get": operation("/api/products", "read", "products.list")},
            "/api/products/{id}": {
                "get": operation("/api/products/{id}", "read", "products.get", [product_parameter])
            },
            "/api/products/{id}/manual": {
                "get": operation(
                    "/api/products/{id}/manual", "download", "products.manual", [product_parameter]
                )
            },
        },
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "PublicCatalogFixture/1"

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
        query = parse_qs(parsed.query)
        if path == "/":
            html = b'''<!doctype html><html><head><link rel="service-desc" type="application/openapi+json" href="/openapi.json"></head><body><form action="/api/products" method="get"><input name="q"><button>Search</button></form><script src="/catalog.js"></script></body></html>'''
            self.send_bytes(200, html, "text/html")
        elif path == "/catalog.js":
            self.send_bytes(200, b'fetch("/api/categories"); fetch("/api/products?limit=10");', "application/javascript")
        elif path == "/openapi.json":
            self.send_json(200, openapi())
        elif path == "/healthz":
            self.send_json(200, {"ok": True})
        elif path == "/api/categories":
            self.send_json(200, {"items": sorted({item["category"] for item in PRODUCTS})})
        elif path == "/api/products":
            q = query.get("q", [""])[0].lower()
            category = query.get("category", [""])[0].lower()
            matches = [
                item for item in PRODUCTS
                if (not q or q in item["name"].lower() or q in item["tags"])
                and (not category or item["category"] == category)
            ]
            try:
                start = int(query.get("cursor", ["0"])[0])
                limit = max(1, min(50, int(query.get("limit", ["10"])[0])))
            except ValueError:
                self.send_json(400, {"error": "invalid_cursor_or_limit"})
                return
            fields = [field for field in query.get("fields", [""])[0].split(",") if field]
            page = matches[start:start + limit]
            if fields:
                page = [{field: item[field] for field in fields if field in item} for item in page]
            next_cursor = str(start + limit) if start + limit < len(matches) else None
            self.send_json(200, {"items": page, "next_cursor": next_cursor})
        elif path.startswith("/api/products/"):
            parts = path.strip("/").split("/")
            product_id = parts[2] if len(parts) >= 3 else ""
            product = next((item for item in PRODUCTS if item["id"] == product_id), None)
            if product is None:
                self.send_json(404, {"error": "not_found"})
            elif len(parts) == 4 and parts[3] == "manual":
                self.send_bytes(200, f"%PDF-fixture\nmanual:{product_id}\n".encode(), "application/pdf")
            elif len(parts) == 3:
                self.send_json(200, product)
            else:
                self.send_json(404, {"error": "not_found"})
        else:
            self.send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        if urlparse(self.path).path == "/__fixture/reset":
            if self.control_authorized():
                self.send_json(200, {"reset": True})
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
