MCP Security Scanner (HTTP & SSE)

This is a Python-based security scanner for Model Context Protocol (MCP) servers. It supports Streamable HTTP and SSE transports, runs a suite of checks mapped to `scanner_specs.schema` (auth, transport, tools, prompts, resources), and includes a deliberately insecure MCP-like server for testing.

Note: SSE transport is discontinued in the latest version of MCP. Support for SSE in this tool is purely experimental and may not work!!!


## Install

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


## Usage

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
# Basic (HTTP JSON-RPC). Supports --test modes (see below)
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

### Scan the server (HTTP or SSE)
```bash
# HTTP: Text report (no discovery; --url is the JSON-RPC endpoint)
mcp-scan scan --url http://127.0.0.1:9001/mcp --format text

# HTTP: JSON report
mcp-scan scan --url http://127.0.0.1:9001/mcp --format json --output report.json

# HTTP: Verbose tracing (real-time)
mcp-scan scan --url http://127.0.0.1:9001/mcp --verbose

# SSE: connect to explicit SSE endpoint, then scan via emitted /messages?sessionId=...
mcp-scan scan --url https://your-mcp.example.com --transport sse --sse-endpoint /sse --timeout 30 --verbose
```

### New: RPC passthrough (Inspector-like)
```bash
# List tools
mcp-scan rpc --url https://your-mcp.example.com/mcp --method tools/list --transport http

# Call a tool
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
- Works for HTTP and SSE (SSE uses the provided endpoint and the stream-emitted POST path).
- Supports `--format text` and `--format json`.

Examples:
```bash
# HTTP
mcp-scan scan --url https://your-mcp.example.com/mcp --only-health --format text

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
- **--transport auto|http|sse**: Hint preferred transport; no dynamic discovery. Provide working URLs.
- **--timeout <seconds>**: Per-request read timeout (default 12s). Increase for slow streams.
- **--session-id <SID>**: Pre-established session (`Mcp-Session-Id` header).
- Content negotiation: scanner sends `Accept: application/json, text/event-stream` to support streamable responses.

### Troubleshooting
- 406 Not Acceptable: the scanner now advertises both JSON and SSE in `Accept`.
- SSE responds with `endpoint` then rotates session: the scanner updates the POST URL and `Mcp-Session-Id` automatically.
- Initialize returns SSE: handled transparently; the response body is parsed from the stream.
- Cannot reach server: verify host/port and TLS. Use `--timeout` for long responses.

## Acknowledgements
- Vulnerability ideas inspired by `Damn Vulnerable MCP Server` - https://github.com/harishsg993010/damn-vulnerable-MCP-server
- Ye Wang from Red Hat for all his help in resolving `init` problems with certain MCP servers
