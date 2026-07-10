#!/usr/bin/env python3
"""Measure generated MCP discovery performance from a fixture matrix report."""

from __future__ import annotations

import argparse
import json
import math
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from run_fixture_matrix import (
    EvidenceError,
    FixtureProcess,
    StdioClient,
    _execution_environment,
    redact_value,
    write_json,
)


BUDGETS = {
    "tools_list": 16 * 1024,
    "search": 4 * 1024,
    "describe": 8 * 1024,
    "workflow": 8 * 1024,
    "batch": 16 * 1024,
}
EXECUTION_BUDGETS = {"normal": 8 * 1024, "batch": 16 * 1024}


def percentile(samples: list[float], value: float) -> float:
    if not samples:
        raise EvidenceError("cannot calculate a percentile with no samples")
    ordered = sorted(samples)
    position = max(0, math.ceil((value / 100) * len(ordered)) - 1)
    return round(ordered[position], 3)


def content_capability(response: dict[str, Any]) -> str:
    try:
        text = response["result"]["content"][0]["text"]
        return json.loads(text)["capabilities"][0]["id"]
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise EvidenceError("search_capabilities did not return an ID to benchmark") from exc


def discovery_sequence(client: StdioClient, *, initialize: bool) -> dict[str, int]:
    sizes: dict[str, int] = {}
    if initialize:
        _, sizes["initialize"] = client.request("initialize", {"protocolVersion": "2025-06-18"})
    listed, sizes["tools_list"] = client.request("tools/list", {})
    tools = listed.get("result", {}).get("tools")
    if not isinstance(tools, list):
        raise EvidenceError("tools/list did not return a list")
    searched, sizes["search"] = client.request(
        "tools/call", {"name": "search_capabilities", "arguments": {"query": ""}}
    )
    capability_id = content_capability(searched)
    described, sizes["describe"] = client.request(
        "tools/call", {"name": "describe_capabilities", "arguments": {"ids": [capability_id]}}
    )
    if "result" not in described:
        raise EvidenceError("describe_capabilities did not return a result")
    planned, sizes["workflow"] = client.request(
        "tools/call", {"name": "plan_workflow", "arguments": {"capability_id": capability_id}}
    )
    if "result" not in planned:
        raise EvidenceError("plan_workflow did not return a result")
    return sizes


def assert_budgets(sizes: dict[str, int]) -> None:
    for key in ("tools_list", "search", "describe", "workflow"):
        if sizes.get(key, BUDGETS[key] + 1) > BUDGETS[key]:
            raise EvidenceError(f"{key} exceeded its {BUDGETS[key]} byte envelope budget")
    # execute_capability is defined to use 8KiB for ordinary calls and 16KiB for
    # batch calls.  Discovery-only fixture packages intentionally do not promote
    # arbitrary writes, so this validates the exposed maximum without claiming an
    # unexecuted capability passed an E2E task.
    if BUDGETS["batch"] != 16 * 1024:
        raise EvidenceError("batch output budget must remain 16KiB")


def summarise(samples: list[float], calls: int) -> dict[str, float | int]:
    return {"count": len(samples), "calls": calls, "p50_ms": percentile(samples, 50), "p95_ms": percentile(samples, 95)}


def _copy_live_package(package: Path, destination: Path, base_url: str) -> Path:
    """Point a disposable generated artifact at a newly started fixture.

    Matrix packages intentionally keep the original, now-stopped fixture URL.
    Benchmarking makes a copy so its write/download calls cannot alter the
    release evidence package or mistake a dead server for execution coverage.
    """
    shutil.copytree(package, destination)
    config_path = destination / "runtime-config.json"
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError("generated package runtime config is invalid") from exc
    if not isinstance(config, dict):
        raise EvidenceError("generated package runtime config is invalid")
    config["base_url"] = base_url.rstrip("/")
    config_path.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination


def _execute(client: StdioClient, capability_id: str, arguments: dict[str, Any], *, confirmation: bool) -> tuple[float, int]:
    payload: dict[str, Any] = {"capability_id": capability_id, "arguments": arguments}
    if confirmation:
        payload["confirmation"] = True
    started = time.monotonic()
    response, size = client.request("tools/call", {"name": "execute_capability", "arguments": payload})
    elapsed = (time.monotonic() - started) * 1000
    try:
        json.loads(response["result"]["content"][0]["text"])
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"execute_capability returned malformed content for {capability_id}") from exc
    return elapsed, size


def _execution_workload(site: str, iteration: int, root: Path) -> list[tuple[str, str, dict[str, Any], bool]]:
    """Return safe, representative execute_capability calls for one sample."""
    if site == "public_catalog":
        return [
            ("read", "products.list", {"q": "red", "limit": 1}, False),
            ("download", "products.manual", {"id": "p-1", "download_path": f"benchmark-manual-{iteration}.pdf"}, False),
        ]
    if site == "session_admin":
        return [
            ("read", "items.list", {"limit": 1}, False),
            (
                "write",
                "items.create",
                {
                    "Idempotency-Key": f"benchmark-create-{iteration}",
                    "body": {"name": f"Benchmark {iteration}", "quantity": iteration + 1},
                },
                True,
            ),
            ("batch", "items.batch", {"body": [{"id": "i-1", "quantity": iteration + 2}]}, True),
            ("download", "items.export", {"download_path": f"benchmark-items-{iteration}.csv"}, False),
        ]
    if site == "hybrid_cli":
        output = root / "cli-output" / f"benchmark-report-{iteration}.json"
        return [
            ("read", "projects.get", {"id": "p-1"}, False),
            ("cli", "project.inspect", {"id": "p-1"}, False),
            ("cli", "report.render", {"project": "p-1", "output": str(output)}, True),
            ("cli", "report.verify", {"path": str(output)}, False),
        ]
    raise EvidenceError(f"matrix contains an unsupported fixture site: {site}")


def _execution_benchmark(
    package: Path,
    site: str,
    iterations: int,
    latency_budget_ms: float,
) -> dict[str, Any]:
    """Measure real promoted execution against a fresh local fixture instance."""
    samples: dict[str, list[float]] = {}
    bytes_by_capability: dict[str, int] = {}
    max_by_capability: dict[str, int] = {}
    type_by_capability: dict[str, str] = {}
    fixture = FixtureProcess(site).start()
    try:
        with tempfile.TemporaryDirectory(prefix=f"website-mcp-benchmark-{site}-") as temporary:
            root = Path(temporary)
            environment = _execution_environment(site, root)
            working = _copy_live_package(package, root / "generated", fixture.base_url or "")
            with StdioClient(working, env=environment) as client:
                initialized, _size = client.request("initialize", {"protocolVersion": "2025-06-18"})
                if "result" not in initialized:
                    raise EvidenceError("benchmark generated server did not initialize")
                for iteration in range(iterations):
                    for kind, capability_id, arguments, confirmation in _execution_workload(site, iteration, root):
                        elapsed, size = _execute(client, capability_id, arguments, confirmation=confirmation)
                        budget = EXECUTION_BUDGETS["batch" if kind == "batch" else "normal"]
                        if size > budget:
                            raise EvidenceError(f"{capability_id} exceeded its {budget} byte execution envelope budget")
                        samples.setdefault(capability_id, []).append(elapsed)
                        bytes_by_capability[capability_id] = bytes_by_capability.get(capability_id, 0) + size
                        max_by_capability[capability_id] = max(max_by_capability.get(capability_id, 0), size)
                        type_by_capability[capability_id] = kind
    finally:
        fixture.close()

    capabilities = [
        {
            "capability_id": capability_id,
            "kind": type_by_capability[capability_id],
            "calls": len(values),
            "p50_ms": percentile(values, 50),
            "p95_ms": percentile(values, 95),
            "bytes": bytes_by_capability[capability_id],
            "max_envelope_bytes": max_by_capability[capability_id],
            "budget_bytes": EXECUTION_BUDGETS["batch" if type_by_capability[capability_id] == "batch" else "normal"],
        }
        for capability_id, values in sorted(samples.items())
    ]
    all_samples = [value for values in samples.values() for value in values]
    if not all_samples:
        raise EvidenceError("execution benchmark has no representative calls")
    execution = {
        "calls": len(all_samples),
        "p50_ms": percentile(all_samples, 50),
        "p95_ms": percentile(all_samples, 95),
        "bytes": sum(bytes_by_capability.values()),
        "max_envelope_bytes": max(max_by_capability.values()),
        "budget_assertions": EXECUTION_BUDGETS,
        "capabilities": capabilities,
    }
    if float(execution["p95_ms"]) > latency_budget_ms:
        raise EvidenceError(f"execution p95 latency exceeded configured {latency_budget_ms:g}ms multiplier budget")
    return execution


def benchmark_package(package: Path, site: str, iterations: int, latency_budget_ms: float) -> dict[str, Any]:
    cold_latencies: list[float] = []
    warm_latencies: list[float] = []
    max_envelope = 0
    tools_list_bytes = 0
    cold_calls = 0
    warm_calls = 0
    for _ in range(iterations):
        started = time.monotonic()
        with StdioClient(package) as client:
            sizes = discovery_sequence(client, initialize=True)
        cold_latencies.append((time.monotonic() - started) * 1000)
        assert_budgets(sizes)
        max_envelope = max(max_envelope, *sizes.values())
        tools_list_bytes = max(tools_list_bytes, sizes["tools_list"])
        cold_calls += len(sizes)
    with StdioClient(package) as client:
        # Initialization is intentionally outside warm timing but included in
        # process call accounting, so cold and warm evidence stay comparable.
        initialized = discovery_sequence(client, initialize=True)
        assert_budgets(initialized)
        max_envelope = max(max_envelope, *initialized.values())
        tools_list_bytes = max(tools_list_bytes, initialized["tools_list"])
        warm_calls += len(initialized)
        for _ in range(iterations):
            started = time.monotonic()
            sizes = discovery_sequence(client, initialize=False)
            warm_latencies.append((time.monotonic() - started) * 1000)
            assert_budgets(sizes)
            max_envelope = max(max_envelope, *sizes.values())
            tools_list_bytes = max(tools_list_bytes, sizes["tools_list"])
            warm_calls += len(sizes)
    cold = summarise(cold_latencies, cold_calls)
    warm = summarise(warm_latencies, warm_calls)
    if float(cold["p95_ms"]) > latency_budget_ms or float(warm["p95_ms"]) > latency_budget_ms:
        raise EvidenceError(f"p95 latency exceeded configured {latency_budget_ms:g}ms multiplier budget")
    return {
        "cold": cold,
        "warm": warm,
        "tools_list_bytes": tools_list_bytes,
        "tool_description_token_estimate": max(1, math.ceil(tools_list_bytes / 4)),
        "max_envelope_bytes": max_envelope,
        "output_budget_assertions": {"search": BUDGETS["search"], "describe": BUDGETS["describe"], "batch": BUDGETS["batch"]},
        "execution": _execution_benchmark(package, site, iterations, latency_budget_ms),
    }


def benchmark(matrix: Path, output: Path, *, iterations: int, latency_multiplier: float, baseline_ms: float) -> dict[str, Any]:
    if iterations < 1:
        raise EvidenceError("--iterations must be at least 1")
    if latency_multiplier <= 0 or baseline_ms <= 0:
        raise EvidenceError("latency baseline and multiplier must be positive")
    try:
        report = json.loads(matrix.expanduser().read_text(encoding="utf-8"))
        sites = report["sites"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise EvidenceError("fixture matrix report is invalid") from exc
    if report.get("status") != "ok" or not isinstance(sites, list):
        raise EvidenceError("fixture matrix must be successful before benchmarking")
    budget = baseline_ms * latency_multiplier
    results: list[dict[str, Any]] = []
    for site in sites:
        if not isinstance(site, dict) or site.get("status") != "ok":
            raise EvidenceError("fixture matrix contains a failed site")
        package = Path(str(site.get("generated_package", "")))
        if not (package / "server.py").is_file():
            raise EvidenceError("matrix generated package is missing")
        site_id = site.get("site")
        if not isinstance(site_id, str):
            raise EvidenceError("fixture matrix site is malformed")
        results.append({"site": site_id, **benchmark_package(package, site_id, iterations, budget)})
    result = {
        "version": 1,
        "kind": "mcp_fixture_benchmark",
        "status": "ok",
        "iterations": iterations,
        "latency_baseline_ms": baseline_ms,
        "latency_multiplier": latency_multiplier,
        "latency_budget_ms": budget,
        "budgets": BUDGETS,
        "sites": results,
    }
    write_json(output.expanduser().resolve(), result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--latency-multiplier", type=float, default=5.0)
    parser.add_argument("--latency-baseline-ms", type=float, default=500.0)
    args = parser.parse_args()
    try:
        result = benchmark(args.matrix, args.output, iterations=args.iterations, latency_multiplier=args.latency_multiplier, baseline_ms=args.latency_baseline_ms)
    except (OSError, EvidenceError, ValueError) as exc:
        print(redact_value(str(exc)), file=sys.stderr)
        return 2
    print(json.dumps({"status": result["status"], "output": str(args.output.expanduser().resolve())}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
