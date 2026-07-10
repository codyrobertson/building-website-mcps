# Build an MCP from a website

`building-website-mcps` helps an agent turn a website, web app, public API, or
local CLI into an MCP server. Give it a service you are allowed to use, and it
works through the boring but important parts: how to authenticate, which routes
and actions exist, what is safe to expose, and which actions still need a human
in the loop.

It does not treat a scraped endpoint as ready for production. The skill maps
what it finds, tests it, and only exposes an action after there is real proof it
works.

## Install

Install it for Codex:

```bash
npx building-website-mcps install --target codex
```

Or install it for Claude Code:

```bash
npx building-website-mcps install --target claude
```

The installer puts the skill in your personal skills folder:

| Tool | Location | Use it as |
| --- | --- | --- |
| Codex | `~/.codex/skills/building-website-mcps` | `$building-website-mcps` |
| Claude Code | `~/.claude/skills/building-website-mcps` | `/building-website-mcps` |

It will not replace an existing install unless you add `--force`. To use a
different directory, add `--dest <skills-directory>`.

Claude Code uses the same standard `SKILL.md` layout for personal skills. See
the [Claude Code skills docs](https://code.claude.com/docs/en/skills) for its
skill discovery rules.

## What to ask for

Try one of these:

```text
Use $building-website-mcps to build a safe MCP for this authorized service.

Map this public API, then give me a small MCP for the actions that are actually proven.

Turn this local CLI into an MCP. Do not use a shell or make up commands.
```

The skill keeps a record of its work, so a later agent can pick up where the
last one stopped instead of starting over.

## What you get

For an authorized target, the skill can produce:

- An auth plan that keeps credentials out of saved artifacts.
- An OpenAPI map for HTTP routes and an action graph for UI and CLI work.
- A compact MCP with tools for finding, understanding, planning, and running
  supported actions.
- A companion skill that explains setup and safe use to the next agent.
- Tests for normal use, error cases, full workflows, and response size and
  speed.

It keeps UI-only actions separate from stable HTTP or CLI operations. It also
asks for confirmation before writes and keeps actions hidden until they pass
fresh contract or end-to-end tests.

## What it has been tested against

The repository includes three runnable local apps:

| Example | Covers |
| --- | --- |
| Public catalog | Anonymous reads and document downloads |
| Session admin | Session recovery, CRUD, batch work, imports, exports, and confirmed writes |
| Hybrid CLI | HTTP calls alongside typed local CLI commands |

These are real local HTTP and CLI processes. They are not mocked network calls.

## Run the checks yourself

You only need Python 3.10 or newer:

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

There is also a cold-agent trace in `building-website-mcps/evals/traces/`. It
comes from a real collaboration-agent run, but it is not independent external
agent evidence and its timing and response-size fields were not instrumented.

## Safety

Use this with public surfaces or accounts and data you are allowed to access.
It does not bypass logins, CAPTCHAs, rate limits, or anti-bot protections.
Saved artifacts use secret references instead of raw passwords, cookies, or
tokens.

For the full build contract, see
[`building-website-mcps/SKILL.md`](building-website-mcps/SKILL.md).
