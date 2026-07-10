# Runnable website fixtures

Each fixture is a real local `ThreadingHTTPServer` process. Start one with
`python fixtures/<name>/app.py --port 0`; its first stdout line is readiness JSON
containing the bound loopback port. Fixture-only control routes are deliberately
excluded from published OpenAPI documents and require the per-process
`control_token` from readiness in the `X-Fixture-Control` header.

- `public_catalog`: anonymous HTML, complete OpenAPI, pagination, projection, detail, and manual download.
- `session_admin`: cookie and CSRF auth, CRUD, ETags, idempotency, batch, CSV import/export, 401, and 429 controls. Credentials come from `FIXTURE_ADMIN_USER` and `FIXTURE_ADMIN_PASSWORD`.
- `hybrid_cli`: a deliberately partial OpenAPI plus JavaScript route evidence and a typed, allowlisted local CLI. Report rendering requires an existing output root referenced by `FIXTURE_CLI_OUTPUT_ROOT`.
