#!/usr/bin/env python3
"""Record an explicit, artifact-bound discovery checkpoint decision."""

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

from site_to_mcp.checkpoints import CHECKPOINTS, record_checkpoint
from site_to_mcp.common import ensure_workspace_safe


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("project", type=Path)
    parser.add_argument("checkpoint", choices=sorted(CHECKPOINTS))
    parser.add_argument("--decision", choices=["approve", "reject"], required=True)
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--reason")
    parser.add_argument("--fixture-test", action="store_true")
    args = parser.parse_args()
    workspace = args.project.expanduser().resolve() / ".website-mcp"
    try:
        ensure_workspace_safe(workspace)
        state = json.loads((workspace / "state.json").read_text(encoding="utf-8"))
        target = urlparse(state.get("target", ""))
        if args.fixture_test and target.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("--fixture-test approvals are restricted to loopback targets")
        record = record_checkpoint(
            workspace,
            args.checkpoint,
            args.decision,
            args.artifact,
            args.actor,
            fixture_test=args.fixture_test,
            reason=args.reason,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
