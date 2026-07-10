#!/usr/bin/env python3
"""Standalone stdio entrypoint for a generated Website MCP."""

from pathlib import Path

from website_mcp.protocol import serve


if __name__ == "__main__":
    serve(Path(__file__).with_name("runtime-config.json"))
