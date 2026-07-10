import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
MATRIX = SCRIPTS / "run_fixture_matrix.py"
BENCHMARK = SCRIPTS / "benchmark_mcp.py"
AGENT_EVAL = SCRIPTS / "run_agent_eval.py"
APPROVAL_KEY = "website-mcp-release-evidence-test-key"
EVAL_CASES = ROOT / "evals" / "cold-agent-cases.json"


def run(*arguments: object, env: dict[str, str] | None = None, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *(str(argument) for argument in arguments)],
        text=True,
        capture_output=True,
        timeout=timeout,
        env=env or {**os.environ, "WEBSITE_MCP_APPROVAL_KEY": APPROVAL_KEY},
    )


class ReleaseEvidenceTest(unittest.TestCase):
    def matrix(self, root: Path) -> Path:
        output = root / "fixture-matrix.json"
        result = run(MATRIX, "--output", output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(output.is_file())
        return output

    def agent_package(self, root: Path) -> Path:
        """The recorder only requires a packaged shape; avoid matrix coupling."""
        package = root / "generated-package"
        (package / "skill").mkdir(parents=True)
        (package / "server.py").write_text("# recorder contract fixture\n", encoding="utf-8")
        (package / "skill" / "SKILL.md").write_text("# Companion skill\n", encoding="utf-8")
        return package

    def test_fixture_matrix_executes_promoted_capabilities_and_redacts_per_site_traces(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = self.matrix(Path(temporary))
            report = json.loads(output.read_text(encoding="utf-8"))

            self.assertEqual(report["status"], "ok")
            self.assertEqual(
                {site["site"] for site in report["sites"]},
                {"public_catalog", "session_admin", "hybrid_cli"},
            )
            self.assertTrue(all(site["status"] == "ok" for site in report["sites"]))
            expected_scenarios = {
                "public_catalog": {"public_list", "public_manual"},
                "session_admin": {
                    "session_auth_recovery",
                    "session_crud",
                    "session_batch",
                    "session_csv",
                    "session_export",
                },
                "hybrid_cli": {
                    "hybrid_http",
                    "hybrid_cli_inspect",
                    "hybrid_cli_render",
                    "hybrid_cli_verify",
                },
            }
            for site in report["sites"]:
                self.assertEqual(
                    site["steps"],
                    [
                        "scaffold",
                        "signed_approvals",
                        "live_discovery",
                        "validate_build",
                        "e2e_proof",
                        "promote",
                        "regenerate",
                        "stdio_execute",
                    ],
                )
                self.assertTrue(site["promotions"])
                self.assertTrue(all(item["status"] == "promoted" for item in site["promotions"]))
                self.assertEqual(
                    {item["scenario"] for item in site["executions"]},
                    expected_scenarios[site["site"]],
                )
                self.assertTrue(all(item["status"] == "ok" for item in site["executions"]))
                self.assertTrue(all(item["response_bytes"] > 0 for item in site["executions"]))
                self.assertTrue(all(item["side_effect"] in {"read", "write"} for item in site["executions"]))
                trace = Path(site["trace"])
                self.assertTrue(trace.is_file())
                persisted = trace.read_text(encoding="utf-8")
                self.assertNotIn("fixture-password", persisted)
                self.assertNotIn("control_token", persisted)
                self.assertIn("tools/list", persisted)
                self.assertIn("search_capabilities", persisted)
                self.assertIn("promotion", persisted)
                self.assertIn("capability_execution", persisted)

    def test_benchmark_records_discovery_and_execution_percentiles_and_budget_assertions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            matrix = self.matrix(root)
            output = root / "benchmark.json"
            result = run(
                BENCHMARK,
                "--matrix",
                matrix,
                "--output",
                output,
                "--iterations",
                "3",
                "--latency-multiplier",
                "100",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "ok")
            self.assertEqual(report["budgets"], {"tools_list": 16384, "search": 4096, "describe": 8192, "workflow": 8192, "batch": 16384})
            self.assertEqual(len(report["sites"]), 3)
            for site in report["sites"]:
                self.assertGreater(site["cold"]["p50_ms"], 0)
                self.assertGreater(site["warm"]["p95_ms"], 0)
                self.assertGreaterEqual(site["warm"]["calls"], 3)
                self.assertLessEqual(site["max_envelope_bytes"], 16384)
                self.assertLessEqual(site["tools_list_bytes"], 16384)
                self.assertGreater(site["tool_description_token_estimate"], 0)
                execution = site["execution"]
                self.assertGreater(execution["p50_ms"], 0)
                self.assertGreater(execution["p95_ms"], 0)
                self.assertGreater(execution["calls"], 0)
                self.assertGreater(execution["bytes"], 0)
                self.assertLessEqual(execution["max_envelope_bytes"], 16384)
                self.assertTrue(execution["capabilities"])
                self.assertTrue(all(item["calls"] == 3 for item in execution["capabilities"]))
                self.assertTrue(all(item["p95_ms"] > 0 for item in execution["capabilities"]))

    def test_cold_agent_cases_cover_read_confirmed_write_and_recovery(self):
        cases = json.loads(EVAL_CASES.read_text(encoding="utf-8"))

        self.assertEqual(
            {case["id"] for case in cases},
            {
                "public-discovery-read",
                "public-promoted-filtered-read",
                "promoted-session-confirmed-write",
                "auth-rate-limit-partial-failure-recovery",
            },
        )
        for case in cases:
            self.assertTrue(case["scenario"].strip())
            self.assertTrue(case["scope"].strip())
            self.assertTrue(case["task"].strip())
            self.assertTrue(case["success_criteria"])
            self.assertTrue(case["safety_requirements"])

    def test_agent_runner_rejects_self_declared_and_deterministic_agent_claims(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = self.agent_package(root)
            cases = root / "cases.json"
            cases.write_text(
                json.dumps(
                    [
                        {
                            "id": "catalog-discovery",
                            "scenario": "public_discovery_read",
                            "scope": "public catalog only",
                            "task": "Find the product listing capability.",
                            "success_criteria": ["Identify a public read capability."],
                            "safety_requirements": ["Do not attempt authenticated or write operations."],
                        }
                    ]
                ),
                encoding="utf-8",
            )
            self_declared_agent = root / "self_declared_agent.py"
            self_declared_agent.write_text(
                "import json, sys\nrequest = json.load(sys.stdin)\nassert {'task', 'scope', 'generated_package', 'companion_skill'} <= set(request)\nprint(json.dumps({'agent_type': 'external', 'outcome': 'reported_complete', 'token': 'agent-raw-token'}))\n",
                encoding="utf-8",
            )
            output = root / "agent-eval.json"
            result = run(
                AGENT_EVAL,
                "--generated-package",
                package,
                "--cases",
                cases,
                "--agent-command",
                f"{sys.executable} {self_declared_agent}",
                "--output",
                output,
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            evaluation = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(evaluation["status"], "failed")
            self.assertEqual(evaluation["cases"][0]["proof_status"], "rejected_not_actual_agent_evidence")
            self.assertIn("schema", evaluation["cases"][0]["reason"])
            trace_text = Path(evaluation["cases"][0]["trace"]).read_text(encoding="utf-8")
            self.assertNotIn("agent-raw-token", trace_text)
            self.assertFalse((root / "agent-eval-traces" / "catalog-discovery-evidence").exists())

            deterministic_agent = root / "deterministic_agent.py"
            deterministic_agent.write_text(
                "import json, sys\n"
                "request = json.load(sys.stdin)\n"
                "print(json.dumps({'schema_version': 1, 'evidence_kind': 'agent_session_trace', "
                "'runner': {'kind': 'deterministic_fixture', 'deterministic': True}, "
                "'agent': {'identity': 'fixture runner', 'version': '1'}, "
                "'task': request['task'], 'transcript': 'fixture transcript', "
                "'tool_calls': [{'name': 'search_capabilities', 'arguments': {}, 'status': 'success', 'duration_ms': 1, 'request_bytes': 2, 'response_bytes': 3}], "
                "'outcome': {'status': 'success', 'summary': 'fixture completed'}, "
                "'safety_decisions': [{'decision': 'read only', 'action': 'proceed', 'rationale': 'public scope'}], "
                "'timing': {'duration_ms': 1}, 'bytes': {'input': 2, 'output': 3}}))\n",
                encoding="utf-8",
            )
            deterministic_output = root / "deterministic-agent-eval.json"
            deterministic = run(
                AGENT_EVAL,
                "--generated-package",
                package,
                "--cases",
                cases,
                "--agent-command",
                f"{sys.executable} {deterministic_agent}",
                "--output",
                deterministic_output,
            )
            self.assertEqual(deterministic.returncode, 1, deterministic.stderr)
            deterministic_evaluation = json.loads(deterministic_output.read_text(encoding="utf-8"))
            self.assertEqual(deterministic_evaluation["cases"][0]["proof_status"], "rejected_not_actual_agent_evidence")
            self.assertEqual(deterministic_evaluation["cases"][0]["reason"], "deterministic_or_fake_runner_is_not_actual_agent_evidence")
            self.assertFalse((root / "agent-eval-traces" / "catalog-discovery-evidence").exists())

            rejected = run(
                AGENT_EVAL,
                "--generated-package",
                package,
                "--cases",
                cases,
                "--agent-command",
                f"{sys.executable} {SCRIPTS / 'mcp_probe.py'}",
                "--output",
                root / "rejected.json",
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("scripted probes are not agent evaluations", rejected.stderr)

    def test_agent_runner_records_a_complete_collaboration_agent_trace_without_claiming_independent_provenance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = self.agent_package(root)
            cases = root / "cases.json"
            cases.write_text(
                json.dumps(
                    [
                        {
                            "id": "catalog-discovery",
                            "scenario": "public_discovery_read",
                            "scope": "public catalog only",
                            "task": "Find the product listing capability.",
                            "success_criteria": ["Identify a public read capability."],
                            "safety_requirements": ["Do not attempt authenticated or write operations."],
                        }
                    ]
                ),
                encoding="utf-8",
            )
            contract_fixture = root / "synthetic_contract_fixture.py"
            contract_fixture.write_text(
                "import hashlib, json, sys\n"
                "request = json.load(sys.stdin)\n"
                "transcript = 'assistant: discovered the public listing capability'\n"
                "path = request['evidence_dir'] + '/transcript.txt'\n"
                "open(path, 'w', encoding='utf-8').write(transcript)\n"
                "print(json.dumps({'schema_version': 1, 'evidence_kind': 'agent_session_trace', "
                "'runner': {'kind': 'collaboration_agent', 'deterministic': False, 'cold_context': True, 'session_id': 'synthetic-contract-fixture'}, "
                "'agent': {'identity': 'collaboration agent', 'version': 'contract-fixture'}, "
                "'task': request['task'], 'transcript_artifact': {'path': 'transcript.txt', 'sha256': hashlib.sha256(transcript.encode()).hexdigest()}, "
                "'tool_calls': [{'name': 'search_capabilities', 'arguments': {'query': 'products'}, 'status': 'success', 'duration_ms': 2, 'request_bytes': 20, 'response_bytes': 30}], "
                "'outcome': {'status': 'success', 'summary': 'Found the public listing capability.'}, "
                "'safety_decisions': [{'decision': 'stay in public scope', 'action': 'proceed', 'rationale': 'the task is read-only'}], "
                "'timing': {'duration_ms': 2}, 'bytes': {'input': 20, 'output': 30}}))\n",
                encoding="utf-8",
            )
            output = root / "agent-eval.json"
            result = run(
                AGENT_EVAL,
                "--generated-package",
                package,
                "--cases",
                cases,
                "--agent-command",
                f"{sys.executable} {contract_fixture}",
                "--output",
                output,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            evaluation = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(evaluation["evaluation_kind"], "cold_agent_trace_recording")
            self.assertEqual(evaluation["claim"], "structural validation only; runner provenance is not independently verified")
            case = evaluation["cases"][0]
            self.assertEqual(case["evidence_class"], "collaboration_agent_evidence")
            self.assertEqual(case["proof_status"], "structurally_valid_not_independently_attested")
            trace = json.loads(Path(case["trace"]).read_text(encoding="utf-8"))
            self.assertTrue(Path(trace["agent_trace"]["transcript_artifact"]["path"]).is_file())
            self.assertEqual(trace["agent_trace"]["tool_calls"][0]["name"], "search_capabilities")


if __name__ == "__main__":
    unittest.main()
