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
insecure-mcp-server --host 127.0.0.1 --port 9001 --test 0/1/2/3/4/5/6
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
- The scanner starts with default candidates: `/messages` and `/messages/`.
- It calls `initialize` and extracts any capability strings that look like paths (beginning with `/`).
- It probes those capability-derived paths as JSON-RPC endpoints, trying `{capability}`, `{capability}/message`, and `{capability}/list`.
- The first endpoint that returns a valid JSON-RPC response is cached and then used for all subsequent calls (tools/prompts/resources).
- `--verbose` shows each attempted URL and the final selected endpoint.

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

Notes
- Transports removed: WebSocket and SSE are no longer supported; the scanner is HTTP-only.
- The insecure server is now HTTP (FastAPI + uvicorn) and exposes JSON-RPC endpoints used by the scanner.

Acknowledgements
- Vulnerability ideas inspired by `Damn Vulnerable MCP Server` (`https://github.com/harishsg993010/damn-vulnerable-MCP-server`).

