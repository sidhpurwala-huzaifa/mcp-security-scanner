from __future__ import annotations

import asyncio
import json
import os
from typing import Any, Dict

import websockets


INSECURE_TOOLS = [
    {
        "name": "exec_command",
        "description": "Execute a shell command",
        "inputSchema": {
            "type": "object",
            "properties": {"cmd": {"type": "string"}},
            "required": ["cmd"],
        },
    },
    {
        "name": "read_file",
        "description": "Read any file from disk",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
]


async def handle_message(msg: Dict[str, Any]) -> Dict[str, Any]:
    method = msg.get("method")
    req_id = msg.get("id")
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "1.0",
                "capabilities": {"tools": {}, "resources": {}},
                "sessionId": "insecure-session",
            },
        }
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": INSECURE_TOOLS}}
    if method == "tools/call":
        name = msg.get("params", {}).get("name")
        args = msg.get("params", {}).get("arguments", {})
        if name == "exec_command":
            cmd = args.get("cmd", "")
            try:
                # Insecurely execute commands and return stdout
                stream = os.popen(cmd)
                out = stream.read()
                return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": out}]}}
            except Exception as e:  # noqa: BLE001
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": str(e)}}
        if name == "read_file":
            path = args.get("path", "")
            try:
                data = open(path, "rb").read()
                return {"jsonrpc": "2.0", "id": req_id, "result": {"base64": False, "data": data.decode(errors="ignore")}}
            except Exception as e:  # noqa: BLE001
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": str(e)}}
    if method == "resources/read":
        # No path validation whatsoever
        uri = msg.get("params", {}).get("uri", "")
        if uri.startswith("file://"):
            path = uri[len("file://") :]
            try:
                data = open(path, "rb").read()
                return {"jsonrpc": "2.0", "id": req_id, "result": {"base64": False, "data": data.decode(errors="ignore")}}
            except Exception as e:  # noqa: BLE001
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": str(e)}}
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Only file:// supported"}}
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "Method not found"}}


async def ws_handler(websocket):
    while True:
        raw = await websocket.recv()
        try:
            msg = json.loads(raw)
        except Exception:  # noqa: BLE001
            await websocket.send(json.dumps({"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}}))
            continue
        resp = await handle_message(msg)
        await websocket.send(json.dumps(resp))


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Insecure MCP-like WebSocket server", add_help=False)
    parser.add_argument("--host", default="0.0.0.0")  # insecure bind by default
    parser.add_argument("--port", type=int, default=8765)
    args, _unknown = parser.parse_known_args()

    async def _run() -> None:
        async with websockets.serve(ws_handler, args.host, args.port):
            print(f"Insecure MCP server listening on ws://{args.host}:{args.port}")
            await asyncio.Future()

    asyncio.run(_run())


if __name__ == "__main__":
    main()


