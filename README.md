MCP Security Scanner

This is a Python-based penetration testing tool for Model Context Protocol (MCP) servers. It supports HTTP, stdio, and experimental SSE transports, runs a suite of checks mapped to `scanner_specs.schema` (auth, transport, tools, prompts, resources), and includes a deliberately insecure MCP-like server for testing.

**Note: SSE transport is discontinued in the latest version of MCP. Support for SSE in this tool is purely experimental and may not work!!!**


## Install

### Install a tagged release

Tag `0.1.1` has a known packaging defect: the default scan schema is missing from
the installed package ([#13](https://github.com/sidhpurwala-huzaifa/mcp-security-scanner/issues/13)).
The published [`0.1.2` release](https://github.com/sidhpurwala-huzaifa/mcp-security-scanner/releases/tag/0.1.2)
contains the schema fix. Install it in your virtual environment with:

```bash
python -m pip install --upgrade "git+https://github.com/sidhpurwala-huzaifa/mcp-security-scanner.git@0.1.2"
python -c "from mcp_scanner.spec import load_spec; print(f'Loaded {len(load_spec())} checks')"
```

The historical `0.1.2` tag declares package version `0.1.3`; this metadata mismatch
does not affect schema loading. The tag is preserved as published. This release
predates the HTTP Accept-header fix in [#17](https://github.com/sidhpurwala-huzaifa/mcp-security-scanner/pull/17);
use the current source checkout below if you need that fix too.

### Install from source

```bash
# 1) Clone
git clone https://github.com/sidhpurwala-huzaifa/mcp-security-scanner
cd mcp-security-scanner

# 2) Create venv (Python >= 3.10)
python -m venv .venv
source .venv/bin/activate

# 3) Install dependencies
pip install -r requirements.txt

# 4) (Optional) Dev install for CLI entrypoints
pip install -e .
```

### Verify release packaging

An editable install can hide missing package data. To check actual distributions
from a clean checkout:

```bash
python -m pip install build
python -m build
python scripts/check_distribution.py dist
```

The check requires one wheel and one source distribution in `dist/`. It verifies
both contain the schema, then installs the wheel into a temporary virtual
environment and loads the default checks outside the checkout. CI runs this check
on pull requests, main-branch pushes, and tag pushes.


## Usage

### Scan outcomes and report compatibility

Reports use `schema_version: 2`. Each finding has an authoritative `status`:

| Status | Meaning | Compatibility field `passed` |
| --- | --- | --- |
| `pass` | The check evaluated its evidence and passed | `true` |
| `fail` | The check evaluated its evidence and failed | `false` |
| `error` | A prerequisite failed; the check could not be evaluated | `null` |
| `skipped` | Not evaluated, with the reason in `details` | `null` |

Existing boolean findings can still be read. JSON consumers must handle `null`
and use `status` instead of treating every false-like `passed` value as a
vulnerability. JSON summaries count `passed`, `failed`, `errors`, and `skipped`
separately; severity totals count only failed checks.

HTTP scans stop dependent probes when initialization fails, report a `BASE-01`
error even if a custom spec omits that check, and skip the dependent checks.
Independent TLS/Origin/bind and OAuth-metadata checks can still run. Failed or
malformed tool, prompt, and resource enumerations produce errors for the checks
that require them. Successful empty enumerations produce explicit skips rather
than security passes. A failed second tool listing is an error, not evidence of
a rug pull. Paginated results with more pages are treated as incomplete until
full enumeration support is implemented.

Exit codes for `scan` and `scan-range` are `0` for completion without failures or
errors, `1` for evaluated failures, and `2` for incomplete scans with errors
(errors take precedence over failures). Expected empty-result skips alone do not
make a scan incomplete. CLI argument errors can also return `2`. Scan summaries
go to stderr in JSON mode so stdout remains the report; verbose traces are human
diagnostics and should not be combined with machine parsing.

HTTP health output uses `status: "ok"` or `"error"`, `initialize_http_status`,
`enumeration_status`, and an `errors` mapping. An unavailable enumeration is
`null`; a successfully retrieved empty enumeration is `[]`. `--only-health`
returns `2` on an error and displays unavailable data explicitly.

These reporting gates are the first part of [#18](https://github.com/sidhpurwala-huzaifa/mcp-security-scanner/issues/18).
Shared transport parsing, full initialization negotiation, and legacy transport
repair remain separate work. A legacy endpoint discovery event alone no longer
counts as verified MCP initialization. Existing active-probe verdict heuristics
and standalone `rpc` behavior are not changed by these gates.

### Quick test
```bash
# Verify CLI is available
mcp-scan --help

# Reachability preflight example
mcp-scan scan --url http://127.0.0.1:65000
# -> Will fail fast with a clear error if nothing is listening
```

### Run insecure test server (HTTP)
```bash
# Basic (HTTP JSON-RPC). Supports --test modes (Defaults to 0, otherwise choose a vulnerable model from below)
insecure-mcp-server --host 127.0.0.1 --port 9001

# Test modes currently supported
# --test 0 (default): basic insecure MCP-like server
# --test 1: prompt injection-style vulnerable server
# --test 2: tool poisoning-style vulnerable server
# --test 3: rug-pull tool mutation between listings
# --test 4: excessive permissions (admin tools exposed), private:// resource leakage
# --test 5: token theft (server leaks upstream access tokens to clients)
# --test 6: indirect prompt injection (external resource carries hidden instructions)
# --test 7: remote access control exposure (unauth tool enables remote access)

insecure-mcp-server --host 127.0.0.1 --port 9001 --test 0/1/2/3/4/5/6/7
```

### Scan the server (HTTP, stdio, or SSE)
```bash
# HTTP: Text report (no discovery; --url is the JSON-RPC endpoint)
mcp-scan scan --url http://127.0.0.1:9001/mcp --format text

# HTTP: JSON report
mcp-scan scan --url http://127.0.0.1:9001/mcp --format json --output report.json

# HTTP: Verbose tracing (real-time)
mcp-scan scan --url http://127.0.0.1:9001/mcp --verbose

# stdio: Scan local MCP servers via stdin/stdout
mcp-scan scan --transport stdio --command "npx -y @modelcontextprotocol/server-memory" --format json

# SSE: connect to explicit SSE endpoint, then scan via emitted /messages?sessionId=...
mcp-scan scan --url https://your-mcp.example.com --transport sse --sse-endpoint /sse --timeout 30 --verbose
```

### New: RPC passthrough (Inspector-like)
**Note: RPC commands only support HTTP and SSE transports, not stdio.**

HTTP scanning, RPC, and health checks set `Accept: application/json, text/event-stream`
for MCP requests, replacing HTTPX's default or a custom `Accept` value. Authentication
and other custom headers are preserved. SSE GET requests use `Accept: text/event-stream`.

```bash
# List tools (HTTP)
mcp-scan rpc --url https://your-mcp.example.com/mcp --method tools/list --transport http

# Call a tool (HTTP)
mcp-scan rpc --url https://your-mcp.example.com/mcp \
  --method tools/call \
  --params '{"name":"weather","arguments":{"city":"Paris"}}' \
  --transport http

# With SSE transport
mcp-scan rpc --url https://your-mcp.example.com --method tools/list --transport sse --sse-endpoint /sse
```

### Explanations
- `--explain <ID>` prints a focused explanation for a single finding (e.g., `--explain X-01`). It includes:
  - Test (ID and title)
  - Expected outcome
  - Got (scanner-observed details)
  - Result (why PASS/FAIL)
  - Remediation (from the spec)

Example:
```bash
mcp-scan scan --url https://your-mcp.example.com/mcp --explain X-01
```

### Only health
- `--only-health` prints server details and enumerations without running the full scan.
- Works for HTTP, stdio, and SSE transports.
- Supports `--format text` and `--format json`.

Examples:
```bash
# HTTP
mcp-scan scan --url https://your-mcp.example.com/mcp --only-health --format text

# stdio
mcp-scan scan --transport stdio --command "npx -y @modelcontextprotocol/server-memory" --only-health --format json

# SSE
mcp-scan scan --url https://your-mcp.example.com --transport sse --sse-endpoint /sse --only-health --format json
```

### Authentication
```bash
# Bearer token
mcp-scan scan \
  --url http://your-mcp.example.com/mcp \
  --auth-type bearer \
  --auth-token "$TOKEN"

# OAuth2 Client Credentials
mcp-scan scan \
  --url http://your-mcp.example.com/mcp \
  --auth-type oauth2-client-credentials \
  --token-url https://issuer.example.com/oauth2/token \
  --client-id "$CLIENT_ID" --client-secret "$CLIENT_SECRET" \
  --scope "mcp.read mcp.tools"
```

### Transport, timeouts, session
- **--transport auto|http|stdio|sse**: Hint preferred transport; no dynamic discovery.
  - `http`: Requires `--url` for JSON-RPC endpoint
  - `stdio`: Requires `--command` for local MCP server process
  - `sse`: Requires `--url` and `--sse-endpoint` (experimental)
- **--timeout <seconds>**: Per-request read timeout (default 12s). Increase for slow streams.
- **--session-id <SID>**: Pre-established session (`Mcp-Session-Id` header).


## Testing

### Running Tests
```bash
# Set up environment (if not already done)
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .

# Run all tests
python -m pytest tests/ -v

# Run specific test module
python -m pytest tests/test_stdio_scanner.py -v
python -m pytest tests/test_security_checks.py -v

# Run specific test class
python -m pytest tests/test_stdio_scanner.py::TestStdioIntegration -v
```

### Running with Container

```bash
# Build container

podman build -t mcp-scan .

# Run
podman run --rm mcp-scan scan --url ${MCP_SERVER} --format text
```

## Acknowledgements
- Vulnerability ideas inspired by `Damn Vulnerable MCP Server` - https://github.com/harishsg993010/damn-vulnerable-MCP-server
- Ye Wang from Red Hat for all his help in resolving `init` problems with certain MCP servers
