MCP Security Scanner (HTTP-only)

This is a Python-based security scanner for Model Context Protocol (MCP) servers. It speaks HTTP JSON-RPC only, dynamically discovers endpoints from the initialize response, and runs a suite of checks mapped to `scanner_specs.schema` (auth, transport, tools, prompts, resources). A deliberately insecure MCP-like server is bundled for testing.


## Install

### Using virtualenv (venv)
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

### Using uv
```bash

# 1) Clone
git clone https://github.com/sidhpurwala-huzaifa/mcp-security-scanner
cd mcp-security-scanner

# Option A: Install CLI tools globally for your user (no venv)
# - Installs entrypoints declared in pyproject.toml and resolves all requirements
uv tool install --path .
# Ensure uv's bin dir is on PATH (e.g., ~/.local/bin)
mcp-scan --help
insecure-mcp-server --help

# Option B: Install requirements with uv, then run locally (no venv)
# - Installs packages listed in requirements.txt into your current Python environment
# - Prefer a dedicated interpreter or container if avoiding virtualenvs
uv pip install -r requirements.txt

# Run (module entrypoints without installing the package)
uv run -m insecure_mcp_server.server --host 127.0.0.1 --port 9001 --test 7
uv run -m mcp_scanner.cli scan --url http://127.0.0.1:9001 --verbose

# Option C: Ephemeral env managed by uv (no persistent install)
uv run -m mcp_scanner.cli --help
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

### Scan the server (HTTP only)
```bash
# Text report
mcp-scan scan --url http://127.0.0.1:9001 --format text

# JSON report
mcp-scan scan --url http://127.0.0.1:9001 --format json --output report.json

# Verbose tracing (prints requests/responses and leaked data)
mcp-scan scan --url http://127.0.0.1:9001 --verbose

# Plain-English explanations (no full packet dump)
mcp-scan scan --url http://127.0.0.1:9001 --explain

# Scan a range of targets
mcp-scan scan-range --host localhost --ports 9001-9010 --scheme http
```

### Authentication (HTTP)
```bash
# Bearer token
mcp-scan scan \
  --url http://your-mcp.example.com \
  --auth-type bearer \
  --auth-token "$TOKEN" \
  --explain

# OAuth2 Client Credentials
mcp-scan scan \
  --url http://your-mcp.example.com \
  --auth-type oauth2-client-credentials \
  --token-url https://issuer.example.com/oauth2/token \
  --client-id "$CLIENT_ID" --client-secret "$CLIENT_SECRET" \
  --scope "mcp.read mcp.tools" \
  --explain
```

### Transport, timeouts, and session
- **--transport auto|http|sse**: Hint preferred transport. Auto will try HTTP first and fall back to SSE discovery when appropriate.
- **--timeout <seconds>**: Per-request read timeout (connect/write/pool are bounded; default 12s). Increase if your server streams slowly.
- **--session-id <SID>**: Use a pre-established session. The scanner will attach `Mcp-Session-Id: <SID>` to all requests.

Examples:
```bash
# Force SSE and raise timeout
mcp-scan scan --url https://your-mcp.example.com --transport sse --timeout 30 --verbose

# Supply a known session id (when the server requires a session before initialize)
mcp-scan scan --url https://your-mcp.example.com --session-id "e61fa6bd-8f7b-4588-a468-7e0d93dfa8bb" --format text

# Auto transport (default) with longer timeout
mcp-scan scan --url https://your-mcp.example.com --transport auto --timeout 25
```

Notes:
- For servers exposing SSE at `/mcp/sse` or `/sse`, the scanner performs a handshake (GET with `Accept: text/event-stream`) and will parse an initial `endpoint` event. If the event contains a path like `/messages?sessionId=...`, the scanner extracts `sessionId`, sets `Mcp-Session-Id`, and uses the derived POST endpoint.
- For cluster/remote deployments, the KF-03 (unsafe bind address) heuristic is treated as an informational warning only.

### How endpoint discovery works
- The scanner starts discovery by posting `initialize` to the base URL (and its trailing slash variant).
- It extracts capability strings that look like paths (beginning with `/`).
- It probes capability-derived endpoints `{capability}`, `{capability}/message`, `{capability}/list` and caches the first that works.
- All subsequent calls use the discovered endpoint. `--verbose` shows each attempt and the selected endpoint.

### Troubleshooting
- "Cannot reach MCP server": Ensure the host/port are correct and the server is running.
- 400/404 on base URL: The scanner will still attempt capability-derived endpoints if initialize succeeds.
- Auth failures: Use `--auth-type bearer --auth-token ...` or OAuth2 client-credentials flags.
- macOS/Linux shells: Always `source .venv/bin/activate` before running commands.

### Capabilities (checks)
- Multi-target scanning: port ranges via scan-range
- Verbose mode: full request/response trace and leakage evidence
- Explain mode: plain-English what-was-sent/received/expected and exploited capability
- Authenticated scans: bearer token or OAuth2 client-credentials
- Findings mapped to `scanner_specs.schema` (examples):
  - T-02 TLS enforcement & HSTS
  - A-01 Unauthenticated access
  - X-01 Dangerous tool exposure without constraints
  - P-02 Prompt/description injection heuristics (tool poisoning)
  - X-03 Tool description stability (rug-pull detection)
  - R-01 Path traversal attempts via resources
  - R-03 Sensitive resource exposure (credentials/tokens)
  - R-04 User-controlled resource templates without validation
  - R-05 Private resource exposure (e.g., private://)
  - A-03 Token pass-through exposure (upstream token leakage)
  - P-03 Indirect prompt injection via external resources
  - RC-01 Remote access control exposure (detects unauth tools that enable remote access)

### Example: Remote access control (RC-01)
```bash
# Start vulnerable mode
insecure-mcp-server --host 127.0.0.1 --port 9001 --test 7

# Scan
mcp-scan scan --url http://127.0.0.1:9001 --verbose
```
If a tool like `enable_remote_access` is exposed and can be invoked without auth, the scanner reports RC-01 (critical) with evidence.

## Acknowledgements
- Vulnerability ideas inspired by `Damn Vulnerable MCP Server` - https://github.com/harishsg993010/damn-vulnerable-MCP-server
