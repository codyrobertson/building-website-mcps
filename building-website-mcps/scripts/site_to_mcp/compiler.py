from __future__ import annotations

import copy
import json
import os
import re
import shutil
import tempfile
from contextlib import contextmanager
from uuid import uuid4
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from .common import (
    canonical,
    ensure_workspace_safe,
    fresh_until,
    has_url_userinfo,
    now,
    append_jsonl_sequenced,
    redact_headers,
    redact_json_object,
    redact_text,
    redact_url,
    same_origin,
    sha256_bytes,
    write_bytes_atomic,
    write_json_atomic,
)
from .html_surface import SurfaceParser
from transition_stage import _lock_file as _transition_lock_file
from transition_stage import _unlock_file as _transition_unlock_file


METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
JS_ROUTE = re.compile(r"[\"'`](/(?:api|v\d+|session)[^\"'` ]+)[\"'`]")
CLI_EXECUTABLE = re.compile(
    r"^(?:env:[A-Z_][A-Z0-9_]*|[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*)$"
)
CLI_PLACEHOLDER = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*\}")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


@contextmanager
def _workspace_transition_lock(project: Path):
    """Use the exact lock file and locking primitive used by transition_stage."""
    lock_path = project / ".website-mcp.lock"
    if lock_path.is_symlink():
        raise ValueError("workspace lock path is a symlink")
    descriptor = os.open(
        lock_path,
        os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(descriptor, "a+", encoding="utf-8") as handle:
        _transition_lock_file(handle)
        try:
            yield
        finally:
            _transition_unlock_file(handle)


def fetch(url: str) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(url, headers={"Accept": "application/json,text/html,*/*"})
    try:
        opener = urllib.request.build_opener(_NoRedirect())
        with opener.open(request, timeout=5) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


class Compiler:
    def __init__(self, project: Path, target: str) -> None:
        self.project = project.resolve()
        self.workspace = self.project / ".website-mcp"
        ensure_workspace_safe(self.workspace)
        parsed = urlparse(target)
        self.cli_only = parsed.scheme == "cli"
        if self.cli_only:
            if (
                parsed.netloc != "local"
                or has_url_userinfo(target)
                or parsed.path
                or parsed.params
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("target must be the credential-free CLI target cli://local")
            self.target = target
        else:
            self.target = target.rstrip("/")
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or has_url_userinfo(target)
            ):
                raise ValueError("target must be a credential-free HTTP(S) origin")
        try:
            self.evidence_index = json.loads(
                (self.workspace / "evidence-index.json").read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("malformed evidence-index.json") from exc
        if (
            not isinstance(self.evidence_index, dict)
            or not isinstance(self.evidence_index.get("records"), list)
        ):
            raise ValueError("malformed evidence-index.json")
        self.evidence_ids: list[str] = []
        self.forms: list[dict[str, str]] = []
        self.script_routes: set[str] = set()
        self.script_route_evidence: dict[str, str] = {}
        self.model_changes: list[str] = []
        self.pending_evidence: dict[Path, bytes] = {}
        self.pending_documents: dict[Path, object] = {}
        self.coverage: dict[str, Any] | None = None

    def capture(
        self, url: str, status: int, headers: dict[str, str], body: bytes, kind: str
    ) -> str:
        if has_url_userinfo(url):
            raise ValueError("discovery URL must be credential-free before capture")
        text = body.decode("utf-8", errors="replace")
        redacted, redactions = redact_text(text)
        safe_url, url_redactions = redact_url(url)
        safe_headers, header_redactions = redact_headers(headers)
        evidence_headers = {
            key: value
            for key, value in safe_headers.items()
            if value == "[REDACTED]"
        }
        content_type = next(
            (
                value
                for key, value in safe_headers.items()
                if key.lower() == "content-type"
            ),
            "",
        ).split(";", 1)[0]
        content = {
            "url": safe_url,
            "status": status,
            "content_type": content_type,
            "headers": evidence_headers,
            "body": redacted,
        }
        encoded = json.dumps(content, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        digest = sha256_bytes(encoded)
        evidence_id = f"discovery-{digest[:16]}"
        relative = f"evidence/{evidence_id}.json"
        evidence_dir = self.workspace / "evidence"
        artifact = self.workspace / relative
        self.pending_evidence[artifact] = encoded
        known = {record.get("id") for record in self.evidence_index.get("records", [])}
        if evidence_id not in known:
            self.evidence_index["records"].append(
                {
                    "id": evidence_id,
                    "kind": kind,
                    "source": safe_url,
                    "captured_at": now(),
                    "fresh_until": fresh_until(),
                    "scope": "discovery",
                    "redactions": list(dict.fromkeys([*redactions, *url_redactions, *header_redactions])),
                    "redaction_verified": True,
                    "artifact": relative,
                    "sha256": digest,
                }
            )
        self.evidence_ids.append(evidence_id)
        return evidence_id

    def capture_url(self, url: str, kind: str) -> tuple[int, bytes, str]:
        if self.cli_only:
            raise ValueError("CLI-only targets do not permit HTTP observation")
        if not same_origin(self.target, url):
            raise ValueError(f"discovery URL must be same-origin: {url}")
        status, headers, body = fetch(url)
        evidence_id = self.capture(url, status, headers, body, kind)
        return status, body, evidence_id

    def capture_cli(self, contract_path: Path) -> tuple[dict[str, Any], str]:
        path = contract_path.resolve(strict=True)
        body = path.read_bytes()
        try:
            contract = json.loads(body)
        except json.JSONDecodeError as exc:
            raise ValueError("CLI contract must be valid JSON") from exc
        if not isinstance(contract, dict):
            raise ValueError("CLI contract must be a JSON object")
        evidence_id = self.capture(path.as_uri(), 200, {"Content-Type": "application/json"}, body, "source-code")
        return contract, evidence_id

    def observe(self, explicit_openapi: str | None) -> tuple[dict[str, Any], str, dict[str, Any] | None]:
        if self.cli_only:
            raise ValueError("CLI-only targets do not permit HTTP observation")
        root_url = self.target + "/"
        _, html_body, _ = self.capture_url(root_url, "route-discovery")
        parser = SurfaceParser()
        try:
            parser.feed(html_body.decode("utf-8", errors="replace"))
            parser.close()
        except (UnicodeError, ValueError) as exc:
            raise ValueError("malformed HTML surface") from exc
        self.forms.extend(parser.forms)
        for script in parser.scripts:
            script_url = urljoin(root_url, script)
            if same_origin(self.target, script_url):
                status, body, script_evidence = self.capture_url(script_url, "route-discovery")
                if status == 200:
                    text = body.decode("utf-8", errors="replace")
                    for match in JS_ROUTE.findall(text):
                        route = self._normalize_js_route(match)
                        self.script_routes.add(route)
                        self.script_route_evidence[route] = script_evidence

        candidates: list[str] = []
        if explicit_openapi:
            explicit = urljoin(root_url, explicit_openapi)
            if not same_origin(self.target, explicit):
                raise ValueError("explicit OpenAPI URL must be same-origin")
            candidates.append(explicit)
        for link in parser.links:
            candidate = urljoin(root_url, link)
            if candidate.endswith(".json") and same_origin(self.target, candidate):
                candidates.append(candidate)
        candidates.extend(
            [self.target + "/openapi.json", self.target + "/.well-known/openapi.json"]
        )
        seen: set[str] = set()
        selected: tuple[dict[str, Any], str] | None = None
        malformed_openapi = False
        for candidate in candidates:
            if candidate in seen:
                continue
            seen.add(candidate)
            status, body, evidence_id = self.capture_url(candidate, "route-discovery")
            if status != 200:
                continue
            try:
                value = json.loads(body)
            except json.JSONDecodeError:
                malformed_openapi = True
                continue
            if isinstance(value, dict) and str(value.get("openapi", "")).startswith("3.1"):
                selected = value, evidence_id
                break
        if selected is None:
            if malformed_openapi:
                raise ValueError("malformed OpenAPI document")
            raise ValueError("no supported same-origin OpenAPI 3.1 document found")
        return selected[0], selected[1], None

    @staticmethod
    def _normalize_js_route(route: str) -> str:
        return re.sub(r"\$\{[^}]+\}", "{id}", route.split("?", 1)[0])

    def compile(
        self, source: dict[str, Any], openapi_evidence: str | None, cli_contract: Path | None
    ) -> tuple[str, bool]:
        if not isinstance(source, dict):
            raise ValueError("OpenAPI document must be an object")
        if not str(source.get("openapi", "")).startswith("3.1"):
            raise ValueError("OpenAPI document must use version 3.1")
        if not isinstance(source.get("paths"), dict):
            raise ValueError("OpenAPI paths must be an object")
        document = redact_json_object(copy.deepcopy(source))
        document["servers"] = [] if self.cli_only else [{"url": self.target}]
        paths = document["paths"]
        graph_nodes: list[dict[str, Any]] = []
        gaps: list[dict[str, Any]] = []
        auth_required = False
        root_security = document.get("security", [])
        if not isinstance(root_security, list):
            raise ValueError("OpenAPI security must be an array")
        anonymous_used = False
        protected_used = False
        operation_ids: set[str] = set()

        for route, path_item in paths.items():
            if not isinstance(path_item, dict):
                raise ValueError("OpenAPI path items must be objects")
            for method, operation in path_item.items():
                if method.lower() not in METHODS or not isinstance(operation, dict):
                    continue
                operation_id = operation.get("operationId")
                if not isinstance(operation_id, str) or not operation_id:
                    operation_id = self._operation_id(method, route)
                    operation["operationId"] = operation_id
                operation_ids.add(operation_id)
                unsupported_refs = self._omit_external_refs(operation)
                marker = operation.get("x-mcp")
                if not isinstance(marker, dict):
                    marker = {}
                    operation["x-mcp"] = marker
                marker_evidence = marker.get("evidence", [])
                if not isinstance(marker_evidence, list):
                    raise ValueError("OpenAPI x-mcp evidence must be an array")
                marker["route"] = route
                marker["type"] = marker.get("type") if marker.get("type") in {
                    "auth", "read", "create", "update", "delete", "action", "upload", "download"
                } else self._type(method, route)
                form_routes = {form["action"] for form in self.forms}
                marker["surface"] = (
                    marker.get("surface")
                    if marker.get("surface") in {"http", "hybrid"}
                    else ("hybrid" if route in form_routes or route in self.script_routes else "http")
                )
                marker["evidence"] = list(dict.fromkeys([*marker_evidence, openapi_evidence]))
                if "security" in operation and not isinstance(operation["security"], list):
                    raise ValueError("OpenAPI operation security must be an array")
                effective_security = operation.get("security", root_security)
                protected = bool(effective_security)
                auth_required = auth_required or protected
                protected_used = protected_used or protected
                anonymous_used = anonymous_used or not protected
                node = {
                    "id": operation_id,
                    "intent": operation.get("summary") or operation_id.replace(".", " "),
                    "surface": marker["surface"],
                    "operations": [operation_id],
                    "commands": [],
                    "native": "candidate",
                    "execution": self._execution(marker["type"], route),
                    "auth": ["observed-auth" if protected else "anonymous"],
                    "side_effect": self._side_effect(marker["type"]),
                    "confirmation": "required for live writes" if marker["type"] in {"create", "update", "delete", "action", "upload"} else "none",
                    "evidence": [openapi_evidence],
                    "confidence": "observed",
                }
                graph_nodes.append(node)
                reasons = self._operation_gaps(operation, marker["type"])
                if unsupported_refs:
                    reasons.append(
                        f"{unsupported_refs} external OpenAPI reference(s) were omitted"
                    )
                gaps.append(self._gap(operation_id, openapi_evidence, "; ".join(reasons) or "Native promotion awaits checkpoint"))

        cli_document: dict[str, Any] = {"version": 2, "commands": []}
        cli_evidence: str | None = None
        if cli_contract:
            contract, cli_evidence = self.capture_cli(cli_contract)
            execution = contract.get("execution", {})
            if not isinstance(execution, dict):
                raise ValueError("CLI contract execution must be an object")
            if execution.get("mode") != "argv" or execution.get("shell") is not False:
                raise ValueError("CLI contract must use argv mode with shell=false")
            commands = contract.get("commands", [])
            if not isinstance(commands, list):
                raise ValueError("CLI contract commands must be an array")
            executable_ref = execution.get("executable_ref")
            if (
                not isinstance(executable_ref, str)
                or not CLI_EXECUTABLE.fullmatch(executable_ref)
                or ".." in executable_ref.split("/")
            ):
                raise ValueError("CLI contract executable_ref is unsafe")
            output_root_ref = execution.get("output_root_ref")
            if output_root_ref is not None and (
                not isinstance(output_root_ref, str)
                or not re.fullmatch(r"env:[A-Z_][A-Z0-9_]*", output_root_ref)
            ):
                raise ValueError("CLI contract output_root_ref must be an environment reference")
            cli_document["execution"] = {
                "mode": "argv",
                "shell": False,
                "output_root_ref": output_root_ref,
            }
            for raw in commands:
                if not isinstance(raw, dict) or not isinstance(raw.get("id"), str) or not raw["id"]:
                    raise ValueError("CLI contract commands require non-empty string IDs")
                command_id = raw["id"]
                argv = raw.get("argv")
                if (
                    not isinstance(argv, list)
                    or not argv
                    or not all(isinstance(item, str) and "\x00" not in item and "\n" not in item for item in argv)
                ):
                    raise ValueError("CLI contract commands require a non-empty argv string array")
                properties = raw.get("arguments_schema", {}).get("properties", {})
                if not isinstance(properties, dict):
                    raise ValueError("CLI contract arguments_schema.properties must be an object")
                for item in argv:
                    for placeholder in CLI_PLACEHOLDER.findall(item):
                        if placeholder[1:-1] not in properties:
                            raise ValueError("CLI argv placeholder is not declared by arguments_schema")
                cli_document["commands"].append(
                    {
                        "id": command_id,
                        "executable_ref": executable_ref,
                        "argv": argv,
                        "version_evidence": cli_evidence,
                        "arguments_schema": raw.get("arguments_schema", {"type": "object"}),
                        "stdout_schema": raw.get("stdout_schema", {"type": "object"}),
                        "exit_codes": {"0": "success", "2": "invalid arguments"},
                        "side_effect": raw.get("side_effect", "read"),
                        "timeout_ms": raw.get("timeout_ms", 3000),
                        "evidence": [cli_evidence],
                    }
                )
                graph_nodes.append(
                    {
                        "id": command_id,
                        "intent": command_id.replace(".", " "),
                        "surface": "stdio",
                        "operations": [],
                        "commands": [command_id],
                        "native": "candidate",
                        "execution": "independent",
                        "auth": [],
                        "side_effect": raw.get("side_effect", "read"),
                        "confirmation": "required for live writes" if raw.get("side_effect") == "write" else "none",
                        "evidence": [cli_evidence],
                        "confidence": "observed",
                    }
                )
                gaps.append(self._gap(command_id, cli_evidence, "CLI promotion awaits native-floor checkpoint"))

        for route in sorted(self.script_routes):
            if route in document["paths"]:
                continue
            capability = self._operation_id("get", route)
            graph_nodes.append(
                {
                    "id": capability,
                    "intent": f"Observed UI action {route}",
                    "surface": "ui",
                    "operations": [],
                    "commands": [],
                    "native": "fallback",
                    "execution": "paginated" if "events" in route else "independent",
                    "auth": [],
                    "side_effect": "read",
                    "confirmation": "none",
                    "evidence": list(dict.fromkeys(self.evidence_ids)),
                    "confidence": "observed",
                }
            )
            gaps.append(
                self._gap(
                    capability,
                    self.script_route_evidence[route],
                    "Route observed in JavaScript but absent from OpenAPI",
                )
            )

        discovery_evidence = openapi_evidence or cli_evidence
        if not isinstance(discovery_evidence, str):
            raise ValueError("discovery is missing HTTP or CLI evidence")
        modes: list[dict[str, Any]] = []
        if protected_used:
            modes.append(
                {
                    "id": "observed-auth",
                    "kind": "cookie-session",
                    "evidence": [discovery_evidence],
                    "confidence": "observed",
                }
            )
        if anonymous_used or not protected_used:
            modes.append(
                {
                    "id": "anonymous",
                    "kind": "anonymous",
                    "evidence": [discovery_evidence],
                    "confidence": "observed",
                }
            )
        auth = {
            "version": 2,
            "status": "observed" if auth_required else "anonymous",
            "modes": modes,
            "secret_policy": "references-only",
            "evidence": [discovery_evidence],
        }
        graph = {"version": 2, "nodes": graph_nodes, "edges": []}
        coverage = {
            "version": 2,
            "route_counts": {"observed": len(operation_ids), "modeled": len(operation_ids), "verified": 0},
            "action_counts": {"observed": len(graph_nodes), "native": 0, "verified": 0},
            "gaps": gaps,
        }
        self.coverage = coverage
        self.pending_documents = {
            self.workspace / "openapi.json": document,
            self.workspace / "auth.json": auth,
            self.workspace / "cli.json": cli_document,
            self.workspace / "action-graph.json": graph,
            self.workspace / "coverage.json": coverage,
            self.workspace / "evidence-index.json": self.evidence_index,
        }
        self.model_changes.extend(
            [
                f"modeled {len(operation_ids)} HTTP operations",
                f"modeled {len(cli_document['commands'])} CLI commands",
                f"recorded {len(gaps)} explicit coverage gaps",
            ]
        )
        digest = sha256_bytes(canonical(sorted(set(self.evidence_ids))))
        return digest, auth_required

    def compile_cli(self, cli_contract: Path) -> tuple[str, bool]:
        """Compile a local CLI contract without making any HTTP observation."""
        if not self.cli_only:
            raise ValueError("CLI-only compilation requires target cli://local")
        return self.compile(
            {
                "openapi": "3.1.0",
                "info": {"title": "Discovered local CLI capabilities", "version": "0.0.0"},
                "paths": {},
            },
            None,
            cli_contract,
        )

    def commit(self) -> None:
        """Persist a fully prepared discovery candidate only after preflight succeeds."""
        if self.coverage is None:
            raise ValueError("discovery candidate must be compiled before commit")
        with _workspace_transition_lock(self.project):
            self._preflight_commit()
            parent = self.workspace.parent
            temporary_root = Path(tempfile.mkdtemp(prefix=".website-mcp.commit.", dir=parent))
            staged = temporary_root / self.workspace.name
            backup = parent / f".website-mcp.commit-old.{os.getpid()}.{uuid4().hex}"
            try:
                ensure_workspace_safe(self.workspace)
                shutil.copytree(self.workspace, staged)
                ensure_workspace_safe(self.workspace)
                ensure_workspace_safe(staged)
                for path, content in self.pending_evidence.items():
                    staged_path = staged / path.relative_to(self.workspace)
                    staged_path.parent.mkdir(parents=True, exist_ok=True)
                    write_bytes_atomic(staged_path, content)
                for path, document in self.pending_documents.items():
                    staged_path = staged / path.relative_to(self.workspace)
                    write_json_atomic(staged_path, document)
                ensure_workspace_safe(self.workspace)
                ensure_workspace_safe(staged)
                os.replace(self.workspace, backup)
                try:
                    ensure_workspace_safe(staged)
                    os.replace(staged, self.workspace)
                except BaseException:
                    ensure_workspace_safe(backup)
                    os.replace(backup, self.workspace)
                    raise
                shutil.rmtree(backup)
            finally:
                shutil.rmtree(temporary_root, ignore_errors=True)

    def _preflight_commit(self) -> None:
        ensure_workspace_safe(self.workspace)
        expected_documents = {
            self.workspace / name
            for name in (
                "openapi.json",
                "auth.json",
                "cli.json",
                "action-graph.json",
                "coverage.json",
                "evidence-index.json",
            )
        }
        if set(self.pending_documents) != expected_documents:
            raise ValueError("discovery commit is missing managed artifacts")
        for path in expected_documents:
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"managed artifact is unsafe: {path.name}")
        evidence_dir = self.workspace / "evidence"
        if evidence_dir.exists() and (evidence_dir.is_symlink() or not evidence_dir.is_dir()):
            raise ValueError("managed evidence directory is unsafe")
        for path in self.pending_evidence:
            try:
                path.relative_to(evidence_dir)
            except ValueError as exc:
                raise ValueError("discovery evidence path is unsafe") from exc
            if path.exists() and (path.is_symlink() or not path.is_file()):
                raise ValueError(f"managed evidence artifact is unsafe: {path.name}")

    @staticmethod
    def _operation_id(method: str, route: str) -> str:
        words = re.sub(r"[^A-Za-z0-9]+", ".", route).strip(".") or "root"
        return f"{method.lower()}.{words}"

    @staticmethod
    def _type(method: str, route: str) -> str:
        if "session" in route or "login" in route:
            return "auth"
        if "upload" in route or "import" in route:
            return "upload"
        if "download" in route or route.endswith((".csv", "/manual")):
            return "download"
        return {"get": "read", "post": "create", "put": "update", "patch": "update", "delete": "delete"}.get(method.lower(), "action")

    @staticmethod
    def _execution(kind: str, route: str) -> str:
        if "batch" in route:
            return "batch"
        if kind == "upload":
            return "upload-stream"
        if kind == "download":
            return "download-stream"
        if kind == "read" and route.endswith("s"):
            return "paginated"
        return "independent"

    @staticmethod
    def _side_effect(kind: str) -> str:
        if kind in {"read", "download", "auth"}:
            return "read"
        if kind == "delete":
            return "destructive"
        return "write"

    @staticmethod
    def _operation_gaps(operation: dict[str, Any], kind: str) -> list[str]:
        reasons: list[str] = []
        if kind in {"create", "update", "action", "upload", "auth"} and not isinstance(operation.get("requestBody"), dict):
            reasons.append("request body schema is unproven")
        if any(key in operation for key in ("callbacks", "webhooks")):
            reasons.append("callbacks or webhooks are unsupported")
        return reasons

    @staticmethod
    def _omit_external_refs(value: object) -> int:
        omitted = 0
        if isinstance(value, dict):
            reference = value.get("$ref")
            if isinstance(reference, str) and not reference.startswith("#"):
                value.pop("$ref")
                value["x-mcp-unsupported-ref"] = "external reference omitted"
                value.setdefault("description", "External reference omitted during discovery")
                omitted += 1
            for child in list(value.values()):
                omitted += Compiler._omit_external_refs(child)
        elif isinstance(value, list):
            for child in value:
                omitted += Compiler._omit_external_refs(child)
        return omitted

    @staticmethod
    def _gap(capability: str, evidence: str, impact: str) -> dict[str, Any]:
        return {
            "id": f"gap-{re.sub(r'[^A-Za-z0-9.-]+', '-', capability)}",
            "capability": capability,
            "impact": impact,
            "evidence": [evidence],
            "workaround": "Use the observed HTTP/UI/CLI surface after explicit approval",
            "owner": "discovery-lead",
            "disposition": "open",
        }


def record_iteration(
    workspace: Path,
    target: str,
    *,
    result: str,
    evidence: list[str],
    model_changes: list[str],
    next_probe: str,
    evidence_digest: str | None,
) -> None:
    ensure_workspace_safe(workspace)
    append_jsonl_sequenced(
        workspace / "discovery-iterations.jsonl",
        lambda seq: {
            "seq": seq,
            "at": now(),
            "target": target,
            "hypothesis": "Published and browser-visible surfaces describe agent-relevant capabilities",
            "planned_observations": [
                "GET root HTML",
                "probe same-origin /openapi.json and /.well-known/openapi.json",
                "inspect linked forms and scripts without executing writes",
            ],
            "evidence": evidence,
            "result": result,
            "model_changes": model_changes,
            "next_probe": next_probe,
            "evidence_digest": evidence_digest,
        },
    )
