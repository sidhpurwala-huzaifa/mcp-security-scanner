MCP Security Scanner (HTTP-only)

Install
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

Run insecure test server (HTTP)
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

Scan the server (HTTP only)
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

Authentication (HTTP)
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

How endpoint discovery works
- The scanner starts discovery by posting `initialize` to the base URL (and its trailing slash variant).
- It extracts capability strings that look like paths (beginning with `/`).
- It probes capability-derived endpoints `{capability}`, `{capability}/message`, `{capability}/list` and caches the first that works.
- All subsequent calls use the discovered endpoint. `--verbose` shows each attempt and the selected endpoint.

Capabilities (checks)
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

Example: Remote access control (RC-01)
```bash
# Start vulnerable mode
insecure-mcp-server --host 127.0.0.1 --port 9001 --test 7

# Scan
mcp-scan scan --url http://127.0.0.1:9001 --verbose
```
If a tool like `enable_remote_access` is exposed and can be invoked without auth, the scanner reports RC-01 (critical) with evidence.

Notes
- Transports removed: WebSocket and SSE are no longer supported; the scanner is HTTP-only.
- The insecure server is HTTP (FastAPI + uvicorn) and exposes JSON-RPC endpoints discovered dynamically by the scanner.

Acknowledgements
- Vulnerability ideas inspired by `Damn Vulnerable MCP Server` - https://github.com/harishsg993010/damn-vulnerable-MCP-server
