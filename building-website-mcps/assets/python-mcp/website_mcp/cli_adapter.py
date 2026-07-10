"""Allowlisted local CLI adapter. It never evaluates shell input."""

from __future__ import annotations

import json
import os
import re
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


class CliAdapter:
    def __init__(self, config: dict[str, Any]) -> None:
        commands = config.get("cli", {}).get("commands", [])
        self.commands = {item.get("id"): item for item in commands if isinstance(item, dict)}
        self.max_output = int(config.get("limits", {}).get("max_output_bytes", 64 * 1024))
        self.cli_root_ref = config.get("io", {}).get("cli_root_ref") if isinstance(config.get("io"), dict) else None

    def call(self, command_id: str, arguments: object) -> Any:
        command = self.commands.get(command_id)
        if not isinstance(command, dict) or not isinstance(arguments, dict):
            raise ValueError("unknown_cli_command")
        self._validate_arguments(arguments, command.get("arguments_schema"))
        executable = command.get("executable_ref")
        template = command.get("argv")
        if not isinstance(executable, str) or not isinstance(template, list) or not all(isinstance(item, str) for item in template):
            raise ValueError("cli_contract_is_not_executable")
        argv = [self._expand(item, arguments) for item in template]
        executable_path = Path(executable)
        if executable.startswith("env:"):
            executable = os.environ.get(executable[4:], "")
            executable_path = self._safe_env_executable(executable)
            executable = str(executable_path)
        elif executable_path.is_absolute() or ".." in executable_path.parts:
            raise ValueError("unsafe_cli_executable")
        root = self._safe_cli_root()
        timeout = min(max(int(command.get("timeout_ms", 3000)), 1), 300000) / 1000
        program = [sys.executable, executable] if executable.endswith(".py") else [executable]
        try:
            code, stdout, _stderr = self._stream([*program, *argv], timeout, root)
        except OSError as exc:
            raise ValueError("cli_execution_failed") from exc
        if code != 0:
            raise ValueError(f"cli_exit_{code}")
        try:
            return json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise ValueError("cli_stdout_is_not_json") from exc

    def _safe_cli_root(self) -> Path:
        if not isinstance(self.cli_root_ref, str) or not self.cli_root_ref.startswith("env:"):
            raise ValueError("cli_root_is_not_configured")
        try:
            raw = Path(os.environ[self.cli_root_ref[4:]]).expanduser()
            if raw.is_symlink():
                raise OSError("symlink")
            root = raw.resolve(strict=True)
        except (KeyError, OSError) as exc:
            raise ValueError("cli_root_is_not_configured") from exc
        if not root.is_dir():
            raise ValueError("cli_root_is_not_configured")
        return root

    def _safe_env_executable(self, value: str) -> Path:
        root = self._safe_cli_root()
        raw = Path(value)
        if not raw.is_absolute() or raw.is_symlink():
            raise ValueError("cli_executable_is_unsafe")
        try:
            resolved = raw.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError) as exc:
            raise ValueError("cli_executable_outside_root") from exc
        if not resolved.is_file():
            raise ValueError("cli_executable_is_unsafe")
        return resolved

    def _stream(self, command: list[str], timeout: float, root: Path) -> tuple[int, bytes, bytes]:
        process = subprocess.Popen(
            command, shell=False, cwd=root, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        )
        selector = selectors.DefaultSelector()
        stdout, stderr = bytearray(), bytearray()
        deadline = time.monotonic() + timeout
        try:
            assert process.stdout is not None and process.stderr is not None
            selector.register(process.stdout, selectors.EVENT_READ, stdout)
            selector.register(process.stderr, selectors.EVENT_READ, stderr)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self._terminate_group(process)
                    raise ValueError("cli_timeout")
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    target = key.data
                    target.extend(chunk)
                    if len(stdout) + len(stderr) > self.max_output:
                        self._terminate_group(process)
                        raise ValueError("cli_output_exceeds_byte_limit")
            return process.wait(timeout=max(0.01, deadline - time.monotonic())), bytes(stdout), bytes(stderr)
        finally:
            selector.close()
            if process.poll() is None:
                self._terminate_group(process)
            if process.stdout:
                process.stdout.close()
            if process.stderr:
                process.stderr.close()

    @staticmethod
    def _terminate_group(process: subprocess.Popen[bytes]) -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass

    @staticmethod
    def _expand(value: str, arguments: dict[str, Any]) -> str:
        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in arguments or not isinstance(arguments[name], (str, int, float)):
                raise ValueError("cli_argument_is_invalid")
            rendered = str(arguments[name])
            if "\x00" in rendered or "\n" in rendered or "\r" in rendered:
                raise ValueError("cli_argument_is_invalid")
            return rendered

        return re.sub(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", replace, value)

    @staticmethod
    def _validate_arguments(arguments: dict[str, Any], schema: object) -> None:
        if not isinstance(schema, dict) or schema.get("type") != "object":
            raise ValueError("cli_arguments_schema_is_invalid")
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(properties, dict) or not isinstance(required, list):
            raise ValueError("cli_arguments_schema_is_invalid")
        if any(not isinstance(name, str) or name not in arguments for name in required):
            raise ValueError("cli_argument_is_required")
        if schema.get("additionalProperties") is False and set(arguments) - set(properties):
            raise ValueError("cli_argument_is_not_allowed")
        for name, value in arguments.items():
            rule = properties.get(name)
            if not isinstance(rule, dict):
                continue
            if rule.get("type") == "string" and not isinstance(value, str):
                raise ValueError("cli_argument_must_be_string")
            if rule.get("type") == "integer" and (isinstance(value, bool) or not isinstance(value, int)):
                raise ValueError("cli_argument_must_be_integer")
            pattern = rule.get("pattern")
            if isinstance(pattern, str) and isinstance(value, str) and re.fullmatch(pattern, value) is None:
                raise ValueError("cli_argument_pattern_mismatch")
            enum = rule.get("enum")
            if isinstance(enum, list) and value not in enum:
                raise ValueError("cli_argument_is_not_allowed")
