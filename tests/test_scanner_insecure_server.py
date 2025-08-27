from __future__ import annotations

import asyncio
import multiprocessing
import time

import pytest

from mcp_scanner.scanner import scan_server


def _run_server() -> None:
    from insecure_mcp_server.server import main

    main()


@pytest.fixture(scope="module", autouse=True)
def insecure_server():
    proc = multiprocessing.Process(target=_run_server, daemon=True)
    proc.start()
    time.sleep(0.6)
    yield
    proc.terminate()


def test_scanner_detects_insecure(ws_url: str | None = None) -> None:
    url = ws_url or "ws://127.0.0.1:8765"
    report = scan_server(url)
    severities = report.summary
    assert severities["failed"] >= 3
    ids = {f.id for f in report.findings if not f.passed}
    assert {"A-01", "T-02", "R-01"}.issubset(ids)


