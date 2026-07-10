# Building Website MCPs

A reusable Codex skill for turning an **authorized** website, web application,
public API, or local CLI into a compact, evidence-gated MCP server.

The skill starts with auth and route/action discovery, models each capability
with the required `route`, `type`, and `surface` dimensions, and generates a
standalone MCP only after contract or E2E proof promotes that capability. It is
designed for iterative, multi-turn work: durable state and signed checkpoints
allow a later agent to resume rather than rediscover the target.

## Install

Copy the skill directory into your Codex skills directory:

```bash
git clone https://github.com/codyrobertson/building-website-mcps.git
mkdir -p ~/.codex/skills
cp -R building-website-mcps/building-website-mcps ~/.codex/skills/
```

Then invoke it as `$building-website-mcps`, for example:

```text
Use $building-website-mcps to build a safe MCP for this authorized service.
```

## What it enforces

- Explicit authorization and least-privilege auth discovery; STDIO is treated
  as MCP transport, never as an authentication mode.
- An OpenAPI 3.1 HTTP map plus an action graph that separates HTTP, UI,
  hybrid, and local-CLI surfaces.
- Candidate capabilities by default. Only fresh, hash-bound contract or E2E
  evidence can promote a capability for MCP execution.
- Compact `search`, `describe`, `plan`, and `execute` MCP tools, confirmation
  for writes, bounded batch/file handling, and direct HTTP/CLI adapters.
- Companion generated-skill documentation so a cold agent can configure and
  safely use the generated MCP without build-history context.
- TDD, unit, contract, live-fixture E2E, performance, and cold-agent evidence.

Read the complete operating contract in
[`building-website-mcps/SKILL.md`](building-website-mcps/SKILL.md). It includes
the required iteration stages, artifact contracts, promotion rules, and stop
conditions.

## Proven fixture coverage

The repository contains three runnable, real local fixture sites—not mocked
HTTP calls:

| Fixture | Proves |
| --- | --- |
| Public catalog | Anonymous reads and download-like documentation retrieval |
| Session admin | Cookie/session auth recovery, CRUD, batch, import/export, and confirmed writes |
| Hybrid CLI | HTTP plus typed, no-shell local-CLI operations |

Run the complete deterministic release lane with Python 3.10+:

```bash
WEBSITE_MCP_APPROVAL_KEY=local-fixture-key \
  PYTHONPATH=building-website-mcps/tests \
  python3 building-website-mcps/scripts/run_fixture_matrix.py \
  --output /tmp/website-mcp-matrix.json

python3 building-website-mcps/scripts/benchmark_mcp.py \
  --matrix /tmp/website-mcp-matrix.json \
  --output /tmp/website-mcp-benchmark.json --iterations 5

PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s building-website-mcps/tests -p 'test_*.py' -q
```

The cold-agent trace in `building-website-mcps/evals/traces/` is an actual
collaboration-agent run and is deliberately labelled non-independent; its
timing and response-size fields are uninstrumented. It is useful structural
evidence, not a substitute for an independently attested external agent run.

## Safety boundary

Use this only on public surfaces or accounts/data you are authorized to access.
It explicitly forbids bypassing access controls, CAPTCHAs, rate limits, and
anti-bot protections, and artifacts store secret references—not raw credentials
or cookies.
