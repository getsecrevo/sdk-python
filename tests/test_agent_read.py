from __future__ import annotations

import json
from typing import Callable

import httpx

from secrevo_sdk.client import SecrevoClient

SECRET_PAYLOAD = {
    "workspace_id": "ws-1",
    "secret_id": "sec-123",
    "name": "AMBER_ODOO_AWS",
    "description": "",
    "regeneration_instructions": "",
    "status": "active",
    "updated_at": "2026-07-18T02:00:00Z",
}


def make_client(handler: Callable[[httpx.Request], httpx.Response]) -> SecrevoClient:
    return SecrevoClient(
        base_url="https://api.secrevo.local",
        workspace_id="ws-1",
        token="test-token",
        transport=httpx.MockTransport(handler),
    )


def test_set_agent_read_resolves_and_puts() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/workspaces/ws-1/secrets":
            return httpx.Response(200, json={"secrets": [SECRET_PAYLOAD]})
        if request.url.path == "/v1/workspaces/ws-1/secrets/sec-123/agent-read":
            seen["method"] = request.method
            seen["body"] = json.loads(request.content)
            return httpx.Response(200, json={"agent_raw_read_allowed": True})
        return httpx.Response(404, text=request.url.path)

    make_client(handler).set_agent_read("AMBER_ODOO_AWS", True)
    assert seen["method"] == "PUT"
    assert seen["body"] == {"allowed": True}


def test_set_agent_read_deny_sends_false() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/workspaces/ws-1/secrets":
            return httpx.Response(200, json={"secrets": [SECRET_PAYLOAD]})
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"agent_raw_read_allowed": False})

    make_client(handler).set_agent_read("AMBER_ODOO_AWS", False)
    assert seen["body"] == {"allowed": False}
