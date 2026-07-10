"""Compact capability catalog shared by discovery and execution tools."""

from __future__ import annotations

from typing import Any


def _summary(node: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": node.get("id"),
        "intent": node.get("intent"),
        "surface": node.get("surface"),
        "execution": node.get("execution"),
        "side_effect": node.get("side_effect"),
        "native": node.get("native"),
        "confirmation": node.get("confirmation"),
    }


class Catalog:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.nodes = [node for node in config.get("capabilities", []) if isinstance(node, dict)]

    def search(self, query: str = "") -> list[dict[str, Any]]:
        terms = query.lower().split()
        matches = []
        for node in self.nodes:
            haystack = " ".join(
                str(node.get(key, "")) for key in ("id", "intent", "surface", "side_effect")
            ).lower()
            if all(term in haystack for term in terms):
                matches.append(_summary(node))
        return matches[:50]

    def describe(self, ids: list[str]) -> list[dict[str, Any]]:
        wanted = set(ids)
        results = []
        operations = self.config.get("operations", {})
        commands = self.config.get("cli", {}).get("commands", [])
        by_command = {item.get("id"): item for item in commands if isinstance(item, dict)}
        for node in self.nodes:
            if node.get("id") not in wanted:
                continue
            detail = dict(node)
            detail["operations"] = [
                operations[item] for item in node.get("operations", []) if item in operations
            ]
            detail["commands"] = [
                by_command[item] for item in node.get("commands", []) if item in by_command
            ]
            results.append(detail)
        return results

    def plan(self, capability_id: str) -> dict[str, Any]:
        node = next((item for item in self.nodes if item.get("id") == capability_id), None)
        if node is None:
            raise ValueError("unknown_capability")
        edges = [
            item
            for item in self.config.get("edges", [])
            if isinstance(item, dict) and (item.get("from") == capability_id or item.get("to") == capability_id)
        ]
        return {"capability": _summary(node), "relationships": edges}

    def executable(self, capability_id: str) -> dict[str, Any]:
        node = next((item for item in self.nodes if item.get("id") == capability_id), None)
        if node is None:
            raise ValueError("unknown_capability")
        if node.get("native") != "yes":
            raise ValueError("capability_not_promoted")
        return node


def tool_definitions() -> list[dict[str, Any]]:
    return [
        {
            "name": "search_capabilities",
            "description": "Search the compact capability catalog before loading full contracts.",
            "inputSchema": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "additionalProperties": False,
            },
        },
        {
            "name": "describe_capabilities",
            "description": "Load detailed contracts only for selected capability IDs.",
            "inputSchema": {
                "type": "object",
                "required": ["ids"],
                "properties": {"ids": {"type": "array", "items": {"type": "string"}}},
                "additionalProperties": False,
            },
        },
        {
            "name": "plan_workflow",
            "description": "Inspect a capability's prerequisites and workflow relationships.",
            "inputSchema": {
                "type": "object",
                "required": ["capability_id"],
                "properties": {"capability_id": {"type": "string"}},
                "additionalProperties": False,
            },
        },
        {
            "name": "execute_capability",
            "description": "Execute one promoted, validated HTTP or CLI capability.",
            "inputSchema": {
                "type": "object",
                "required": ["capability_id"],
                "properties": {
                    "capability_id": {"type": "string"},
                    "confirmation": {"type": "boolean"},
                    "arguments": {"type": "object"},
                },
                "additionalProperties": False,
            },
        },
    ]
