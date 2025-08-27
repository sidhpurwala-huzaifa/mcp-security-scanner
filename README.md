MCP Security Scanner

Install
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

Run insecure test server
```bash
insecure-mcp-server --host 0.0.0.0 --port 8765
```

Scan the server
```bash
mcp-scan scan --url ws://127.0.0.1:8765 --format text
mcp-scan scan --url ws://127.0.0.1:8765 --format json --output report.json
```


