MCP Security Scanner

Install
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

Run insecure test server
```bash
# Basic
insecure-mcp-server --host 0.0.0.0 --port 8765

# Testing the MCP scanner:
# Test modes currently supported
# --test 0 (default): basic insecure MCP server
# --test 1: prompt injection-style vulnerable server
# --test 2: tool poisoning-style vulnerable server
# --test 3: rug-pull tool mutation between listings
# --test 4: excessive permissions (admin tools exposed), private:// resource leakage
insecure-mcp-server --host 127.0.0.1 --port 8770 --test 0/1/2/3/4
```

Scan the server
```bash
mcp-scan scan --url ws://127.0.0.1:8765 --format text
mcp-scan scan --url ws://127.0.0.1:8765 --format json --output report.json

# SSE transport (against SSE-capable servers)
mcp-scan scan --url http://localhost:9001 --transport sse --format text

# Verbose tracing (prints requests/responses and leaked data)
mcp-scan scan --url ws://127.0.0.1:8770 --format text --verbose

# Scan a range of targets
mcp-scan scan-range --host localhost --ports 9001-9010 --scheme http
mcp-scan scan-range --host localhost --ports 9001-9010 --scheme sse --verbose
```


Capabilities
- Transports: WebSocket (ws/wss) and SSE (http/https + /sse)
- Multi-target scanning: port ranges via scan-range
- Verbose mode: full request/response trace and leakage evidence
- Findings mapped to scanner_specs.schema (examples):
  - T-02 TLS enforcement & HSTS
  - A-01 Unauthenticated access
  - X-01 Dangerous tool exposure without constraints
  - P-02 Prompt/description injection heuristics (tool poisoning)
  - X-03 Tool description stability (rug-pull detection)
  - R-01 Path traversal attempts via resources
  - R-03 Sensitive resource exposure (credentials/tokens)
  - R-04 User-controlled resource templates without validation
  - R-05 Private resource exposure (e.g., private://)


Acknowledgements:
A lot of attack information have been taken from 
https://github.com/harishsg993010/damn-vulnerable-MCP-server

