# Dependency audit (pip-audit)

Run: `pip install pip-audit && pip-audit -r requirements.txt`

## 2 November 2026

5 known vulnerabilities in 2 packages. Both packages come in only because Semgrep 1.180.0 pins them exactly,
and the newest Semgrep (1.183.0) still pins the same versions, so they cannot be upgraded without breaking Semgrep.

| Package | Version | IDs | What it affects | Reachable in this tool? |
|---|---|---|---|---|
| opentelemetry-api | 1.37.0 (fixed 1.45.1) | CVE-2026-114603 | `TraceState.from_header` is slow (O(N^2)) on a long `tracestate` header | No. The web app does not use OpenTelemetry or read that header; only Semgrep's own telemetry code imports it, and metrics are off (`SEMGREP_SEND_METRICS=off` in the image). |
| mcp | 1.29.0 (fixed 1.30.0) | CVE-2026-59951, CVE-2026-116684, CVE-2026-116685, CVE-2026-116686 | MCP HTTP servers and clients (session cleanup, token audience, redirects, `$ref` fetching) | No. Only the `semgrep mcp` command uses it; this tool never runs it and starts no MCP server or client. |

Decision: accept for now, record here, and recheck when a new Semgrep release relaxes the pins.
The web app's own packages (fastapi, starlette, uvicorn, pydantic, Jinja2, anthropic) had no known vulnerabilities.
