import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote, urlparse

from fixture_harness import FIXTURES, fixture_site, json_request, request


class PublicCatalogFixtureTest(unittest.TestCase):
    def test_readiness_exposes_control_token_and_control_rejects_missing_token(self):
        process = subprocess.Popen(
            [sys.executable, str(FIXTURES / "public_catalog" / "app.py"), "--port", "0"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            ready = json.loads(process.stdout.readline())
            self.assertIsInstance(ready.get("control_token"), str)
            self.assertGreaterEqual(len(ready.get("control_token", "")), 24)
            base = f"http://127.0.0.1:{ready['port']}"
            self.assertEqual(json_request(base, "/__fixture/reset", method="POST")[0], 403)
            self.assertEqual(
                json_request(
                    base,
                    "/__fixture/reset",
                    method="POST",
                    headers={"X-Fixture-Control": ready["control_token"]},
                )[0],
                200,
            )
        finally:
            process.terminate()
            process.wait(timeout=3)
            process.stdout.close()
            process.stderr.close()

    def test_catalog_exposes_real_html_openapi_pagination_projection_and_download(self):
        with fixture_site("public_catalog") as base:
            status, _, html = request(base, "/")
            self.assertEqual(status, 200)
            self.assertIn(b'rel="service-desc"', html)
            self.assertIn(b'action="/api/products"', html)

            status, _, document = json_request(base, "/openapi.json")
            self.assertEqual(status, 200)
            paths = document["paths"]
            self.assertIn("/api/products", paths)
            self.assertNotIn("/healthz", paths)
            self.assertFalse(any(path.startswith("/__fixture") for path in paths))

            status, _, first = json_request(
                base, "/api/products?q=red&fields=id,name,price&limit=1"
            )
            self.assertEqual(status, 200)
            self.assertEqual(set(first["items"][0]), {"id", "name", "price"})
            self.assertEqual(first["items"][0]["id"], "p-1")
            self.assertTrue(first["next_cursor"])
            status, _, second = json_request(
                base,
                "/api/products?q=red&fields=id,name,price&limit=1&cursor="
                + quote(first["next_cursor"]),
            )
            self.assertEqual(status, 200)
            self.assertEqual(second["items"][0]["id"], "p-3")
            self.assertIsNone(second["next_cursor"])

            self.assertEqual(json_request(base, "/api/products/p-1")[0], 200)
            status, headers, manual = request(base, "/api/products/p-1/manual")
            self.assertEqual(status, 200)
            self.assertEqual(headers["Content-Type"], "application/pdf")
            self.assertTrue(manual.startswith(b"%PDF-fixture"))
            self.assertEqual(json_request(base, "/healthz")[0], 200)
            self.assertEqual(
                json_request(
                    base,
                    "/__fixture/reset",
                    method="POST",
                    headers={"X-Fixture-Control": base.control_token},
                )[0],
                200,
            )


class SessionAdminFixtureTest(unittest.TestCase):
    def login(self, base: str) -> tuple[str, str]:
        status, headers, result = json_request(
            base,
            "/session",
            method="POST",
            value={"username": "fixture-admin", "password": "fixture-password"},
        )
        self.assertEqual(status, 200)
        return headers["Set-Cookie"].split(";", 1)[0], result["csrf"]

    def test_empty_credential_environment_fails_closed(self):
        with fixture_site(
            "session_admin",
            {"FIXTURE_ADMIN_USER": "", "FIXTURE_ADMIN_PASSWORD": ""},
        ) as base:
            status, headers, result = json_request(
                base,
                "/session",
                method="POST",
                value={"username": "", "password": ""},
            )
            self.assertEqual(status, 401)
            self.assertNotIn("Set-Cookie", headers)
            self.assertEqual(result, {"error": "auth_not_configured"})

    def test_session_crud_etag_idempotency_batch_and_failure_controls(self):
        env = {
            "FIXTURE_ADMIN_USER": "fixture-admin",
            "FIXTURE_ADMIN_PASSWORD": "fixture-password",
        }
        with fixture_site("session_admin", env) as base:
            self.assertEqual(json_request(base, "/admin")[0], 401)
            cookie, csrf = self.login(base)
            auth = {"Cookie": cookie, "X-CSRF-Token": csrf}
            status, _, created = json_request(
                base,
                "/api/items",
                method="POST",
                value={"name": "Hammer", "quantity": 2},
                headers={**auth, "Idempotency-Key": "create-hammer"},
            )
            self.assertEqual(status, 201)
            repeated = json_request(
                base,
                "/api/items",
                method="POST",
                value={"name": "Ignored", "quantity": 9},
                headers={**auth, "Idempotency-Key": "create-hammer"},
            )[2]
            self.assertEqual(repeated["id"], created["id"])
            status, headers, _ = json_request(base, f"/api/items/{created['id']}", headers=auth)
            self.assertEqual(status, 200)
            etag = headers["ETag"]
            self.assertEqual(
                json_request(
                    base,
                    f"/api/items/{created['id']}",
                    method="PATCH",
                    value={"quantity": 3},
                    headers={**auth, "If-Match": '"wrong"'},
                )[0],
                412,
            )
            self.assertEqual(
                json_request(
                    base,
                    f"/api/items/{created['id']}",
                    method="PATCH",
                    value={"quantity": 3},
                    headers={**auth, "If-Match": etag},
                )[0],
                200,
            )
            operations = [
                {"id": created["id"], "quantity": 4},
                {"id": "missing", "quantity": 1},
            ]
            status, _, batch = json_request(
                base, "/api/items/batch", method="POST", value=operations, headers=auth
            )
            self.assertEqual(status, 207)
            self.assertEqual([entry["status"] for entry in batch["results"]], [200, 404])
            self.assertEqual(
                json_request(
                    base,
                    "/api/items/batch",
                    method="POST",
                    value=[{"id": "x"}] * 21,
                    headers=auth,
                )[0],
                400,
            )

            control = {"X-Fixture-Control": base.control_token}
            self.assertEqual(json_request(base, "/__fixture/expire-session", method="POST", headers=control)[0], 200)
            self.assertEqual(json_request(base, "/api/items", headers=auth)[0], 401)
            cookie, csrf = self.login(base)
            auth = {"Cookie": cookie, "X-CSRF-Token": csrf}
            self.assertEqual(json_request(base, "/__fixture/rate-limit-next", method="POST", headers=control)[0], 200)
            status, headers, _ = json_request(base, "/api/items", headers=auth)
            self.assertEqual(status, 429)
            self.assertIn("Retry-After", headers)
            self.assertEqual(json_request(base, "/api/items", headers=auth)[0], 200)

    def test_idempotency_key_is_atomic_under_concurrent_requests(self):
        env = {
            "FIXTURE_ADMIN_USER": "fixture-admin",
            "FIXTURE_ADMIN_PASSWORD": "fixture-password",
        }
        with fixture_site("session_admin", env) as base:
            cookie, csrf = self.login(base)
            address = urlparse(base)
            body = json.dumps({"name": "Concurrent", "quantity": 1}).encode()
            split = len(body) // 2
            workers = 12
            ready = threading.Barrier(workers)

            def create(_: int) -> tuple[int, str]:
                with socket.create_connection((address.hostname, address.port), timeout=3) as client:
                    request_head = (
                        "POST /api/items HTTP/1.1\r\n"
                        f"Host: {address.hostname}:{address.port}\r\n"
                        f"Cookie: {cookie}\r\n"
                        f"X-CSRF-Token: {csrf}\r\n"
                        "Idempotency-Key: concurrent-create\r\n"
                        "Content-Type: application/json\r\n"
                        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                    ).encode()
                    client.sendall(request_head + body[:split])
                    ready.wait(timeout=3)
                    time.sleep(0.1)
                    client.sendall(body[split:])
                    response = client.makefile("rb")
                    status = int(response.readline().split()[1])
                    content_length = 0
                    while True:
                        line = response.readline()
                        if line in {b"\r\n", b""}:
                            break
                        if line.lower().startswith(b"content-length:"):
                            content_length = int(line.split(b":", 1)[1])
                    result = json.loads(response.read(content_length))
                    return status, result["id"]

            with ThreadPoolExecutor(max_workers=workers) as pool:
                results = list(pool.map(create, range(workers)))
            self.assertEqual(len({item_id for _, item_id in results}), 1)
            listed = json_request(base, "/api/items?limit=50", headers={"Cookie": cookie})[2]
            self.assertEqual(sum(item["name"] == "Concurrent" for item in listed["items"]), 1)

    def test_retry_after_is_valid_integer_seconds(self):
        env = {
            "FIXTURE_ADMIN_USER": "fixture-admin",
            "FIXTURE_ADMIN_PASSWORD": "fixture-password",
        }
        with fixture_site("session_admin", env) as base:
            cookie, _ = self.login(base)
            json_request(
                base,
                "/__fixture/rate-limit-next",
                method="POST",
                headers={"X-Fixture-Control": base.control_token},
            )
            status, headers, _ = json_request(base, "/api/items", headers={"Cookie": cookie})
            self.assertEqual(status, 429)
            self.assertRegex(headers["Retry-After"], r"^[0-9]+$")
            self.assertGreaterEqual(int(headers["Retry-After"]), 1)

    def test_csv_preview_commit_errors_and_export_are_real_downloads(self):
        env = {
            "FIXTURE_ADMIN_USER": "fixture-admin",
            "FIXTURE_ADMIN_PASSWORD": "fixture-password",
        }
        with fixture_site("session_admin", env) as base:
            cookie, csrf = self.login(base)
            auth = {"Cookie": cookie, "X-CSRF-Token": csrf, "Content-Type": "text/csv"}
            status, _, invalid = request(
                base,
                "/api/imports",
                method="POST",
                body=b"name,quantity\nNails,4\nBad,nope\n",
                headers=auth,
            )
            self.assertEqual(status, 200)
            preview = json.loads(invalid)
            self.assertEqual(preview["error_count"], 1)
            self.assertEqual(
                json_request(
                    base,
                    f"/api/imports/{preview['import_id']}/commit",
                    method="POST",
                    headers={"Cookie": cookie, "X-CSRF-Token": csrf},
                )[0],
                409,
            )
            status, headers, errors = request(
                base,
                f"/api/imports/{preview['import_id']}/errors.csv",
                headers={"Cookie": cookie},
            )
            self.assertEqual(status, 200)
            self.assertEqual(headers["Content-Type"], "text/csv")
            self.assertIn(b"invalid quantity", errors)

            valid = json.loads(
                request(
                    base,
                    "/api/imports",
                    method="POST",
                    body=b"name,quantity\nNails,4\n",
                    headers=auth,
                )[2]
            )
            self.assertEqual(
                json_request(
                    base,
                    f"/api/imports/{valid['import_id']}/commit",
                    method="POST",
                    headers={"Cookie": cookie, "X-CSRF-Token": csrf},
                )[0],
                200,
            )
            status, headers, exported = request(
                base, "/api/exports/items.csv", headers={"Cookie": cookie}
            )
            self.assertEqual(status, 200)
            self.assertEqual(headers["Content-Type"], "text/csv")
            self.assertIn(b"Nails,4", exported)
            paths = json_request(base, "/openapi.json")[2]["paths"]
            self.assertFalse(any(path.startswith("/__fixture") for path in paths))


class HybridCliFixtureTest(unittest.TestCase):
    def test_partial_openapi_html_js_events_and_assets_supply_multiple_evidence_sources(self):
        with fixture_site("hybrid_cli") as base:
            self.assertIn(b"/static/project.js", request(base, "/")[2])
            document = json_request(base, "/.well-known/openapi.json")[2]
            self.assertIn("/api/projects", document["paths"])
            self.assertNotIn("/api/projects/{id}/events", document["paths"])
            script = request(base, "/static/project.js")[2]
            self.assertIn(b"/events", script)
            events = json_request(base, "/api/projects/p-1/events?limit=1")[2]
            self.assertEqual(len(events["items"]), 1)
            self.assertTrue(events["next_cursor"])
            status, headers, asset = request(base, "/api/projects/p-2/assets/brief.txt")
            self.assertEqual(status, 200)
            self.assertEqual(headers["Content-Type"], "text/plain")
            self.assertIn(b"Project Two", asset)

    def test_cli_contract_allowlists_typed_inspect_render_and_verify_without_shell(self):
        cli = FIXTURES / "hybrid_cli" / "fixture_cli.py"
        contract = json.loads((FIXTURES / "hybrid_cli" / "cli-contract.json").read_text())
        self.assertEqual(
            contract.get("execution"),
            {
                "mode": "argv",
                "shell": False,
                "executable_ref": "fixture_cli.py",
                "output_root_ref": "env:FIXTURE_CLI_OUTPUT_ROOT",
            },
        )
        self.assertEqual(
            [command["id"] for command in contract["commands"]],
            ["project.inspect", "report.render", "report.verify"],
        )
        inspected = subprocess.run(
            [sys.executable, str(cli), "project", "inspect", "--id", "p-1"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        self.assertEqual(inspected.returncode, 0, inspected.stderr)
        self.assertEqual(json.loads(inspected.stdout)["id"], "p-1")
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.json"
            process_env = dict(os.environ, FIXTURE_CLI_OUTPUT_ROOT=tmp)
            rendered = subprocess.run(
                [
                    sys.executable,
                    str(cli),
                    "report",
                    "render",
                    "--project",
                    "p-1",
                    "--output",
                    str(report),
                ],
                capture_output=True,
                text=True,
                timeout=3,
                env=process_env,
            )
            self.assertEqual(rendered.returncode, 0, rendered.stderr)
            verified = subprocess.run(
                [sys.executable, str(cli), "report", "verify", "--path", str(report)],
                capture_output=True,
                text=True,
                timeout=3,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertTrue(json.loads(verified.stdout)["valid"])

            marker = Path(tmp) / "pwned"
            rejected = subprocess.run(
                [sys.executable, str(cli), "project", "inspect", "--id", f"p-1;touch {marker}"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertFalse(marker.exists())
            unallowlisted = subprocess.run(
                [sys.executable, str(cli), "shell"], capture_output=True, text=True, timeout=3
            )
            self.assertNotEqual(unallowlisted.returncode, 0)

    def test_cli_render_is_root_bounded_exclusive_and_rejects_symlinks(self):
        cli = FIXTURES / "hybrid_cli" / "fixture_cli.py"
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            process_env = dict(os.environ, FIXTURE_CLI_OUTPUT_ROOT=str(root))

            traversal = subprocess.run(
                [sys.executable, str(cli), "report", "render", "--project", "p-1", "--output", "../escape.json"],
                capture_output=True, text=True, timeout=3, env=process_env,
            )
            self.assertNotEqual(traversal.returncode, 0)
            self.assertFalse((root.parent / "escape.json").exists())

            existing = root / "existing.json"
            existing.write_text("keep", encoding="utf-8")
            overwrite = subprocess.run(
                [sys.executable, str(cli), "report", "render", "--project", "p-1", "--output", str(existing)],
                capture_output=True, text=True, timeout=3, env=process_env,
            )
            self.assertNotEqual(overwrite.returncode, 0)
            self.assertEqual(existing.read_text(), "keep")

            outside_target = Path(outside) / "outside.json"
            link = root / "linked.json"
            link.symlink_to(outside_target)
            symlinked = subprocess.run(
                [sys.executable, str(cli), "report", "render", "--project", "p-1", "--output", str(link)],
                capture_output=True, text=True, timeout=3, env=process_env,
            )
            self.assertNotEqual(symlinked.returncode, 0)
            self.assertFalse(outside_target.exists())

    def test_fixture_harness_times_out_silent_startup(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "silent.py"
            script.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
            started = time.monotonic()
            with self.assertRaisesRegex(AssertionError, "readiness timeout"):
                with fixture_site(script, startup_timeout=0.1):
                    pass
            self.assertLess(time.monotonic() - started, 2)


if __name__ == "__main__":
    unittest.main()
