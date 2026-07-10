"""Execute only promoted capabilities through their validated adapter binding."""

from __future__ import annotations

from typing import Any

from .http_adapter import HttpAdapter


class Executor:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.http = HttpAdapter(config)

    def execute(self, node: dict[str, Any], arguments: object) -> Any:
        operations = node.get("operations", [])
        if isinstance(operations, list) and len(operations) == 1 and isinstance(operations[0], str):
            return self.http.call(operations[0], arguments, node.get("auth", []), node.get("side_effect", "read"))
        commands = node.get("commands", [])
        if isinstance(commands, list) and len(commands) == 1 and isinstance(commands[0], str):
            from .cli_adapter import CliAdapter

            return CliAdapter(self.config).call(commands[0], arguments)
        raise ValueError("capability_has_no_single_native_binding")
