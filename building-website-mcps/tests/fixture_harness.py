import json
import os
import queue
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SKILL_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = SKILL_ROOT / "fixtures"


class FixtureAddress(str):
    control_token: str

    def __new__(cls, value: str, control_token: str) -> "FixtureAddress":
        instance = super().__new__(cls, value)
        instance.control_token = control_token
        return instance


@contextmanager
def fixture_site(
    name: str | Path,
    env: dict[str, str] | None = None,
    *,
    startup_timeout: float = 3,
) -> Iterator[FixtureAddress]:
    process_env = dict(os.environ)
    if env:
        process_env.update(env)
    script = name if isinstance(name, Path) else FIXTURES / name / "app.py"
    process = subprocess.Popen(
        [sys.executable, str(script), "--port", "0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=process_env,
    )
    try:
        assert process.stdout is not None
        lines: queue.Queue[str] = queue.Queue(maxsize=1)
        threading.Thread(target=lambda: lines.put(process.stdout.readline()), daemon=True).start()
        try:
            line = lines.get(timeout=startup_timeout)
        except queue.Empty as exc:
            raise AssertionError(f"fixture readiness timeout after {startup_timeout} seconds") from exc
        if not line:
            stderr = process.stderr.read() if process.stderr else ""
            raise AssertionError(f"fixture {name} did not become ready: {stderr}")
        ready = json.loads(line)
        token = ready.get("control_token")
        if not isinstance(token, str) or not token:
            raise AssertionError(f"fixture {name} readiness omitted control_token")
        yield FixtureAddress(f"http://127.0.0.1:{ready['port']}", token)
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        if process.stdout:
            process.stdout.close()
        if process.stderr:
            process.stderr.close()


def request(
    base: str,
    path: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    req = urllib.request.Request(base + path, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=3) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def json_request(
    base: str,
    path: str,
    *,
    method: str = "GET",
    value: object | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], object]:
    request_headers = {"Accept": "application/json", **(headers or {})}
    body = None
    if value is not None:
        body = json.dumps(value).encode()
        request_headers["Content-Type"] = "application/json"
    status, response_headers, raw = request(
        base, path, method=method, body=body, headers=request_headers
    )
    return status, response_headers, json.loads(raw) if raw else None
