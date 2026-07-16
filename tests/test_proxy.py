from __future__ import annotations

import json
from typing import Callable

import httpx
import pytest

from secrevo_sdk import ProxyResponse, ProxySession, ProxyTarget
from secrevo_sdk.client import SecrevoClient

SECRET_PAYLOAD = {
    "workspace_id": "ws-1",
    "secret_id": "sec-123",
    "name": "ODOO",
    "description": "",
    "regeneration_instructions": "",
    "status": "active",
    "updated_at": "2026-05-06T02:00:00Z",
}


def make_client(handler: Callable[[httpx.Request], httpx.Response]) -> SecrevoClient:
    return SecrevoClient(
        base_url="https://api.secrevo.local",
        workspace_id="ws-1",
        token="test-token",
        transport=httpx.MockTransport(handler),
    )


def test_call_posts_to_proxy_and_returns_response() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/workspaces/ws-1/secrets/by-name/ODOO/proxy":
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json={"status": 200, "body": '{"ok":1}', "projected": True})
        return httpx.Response(404, text=request.url.path)

    resp = make_client(handler).call(
        "ODOO", url="https://api.example.com/v1/x", method="POST",
        headers={"Authorization": "Bearer {{secret}}"}, body='{"a":1}',
    )
    assert isinstance(resp, ProxyResponse)
    assert resp.status == 200 and resp.projected is True
    assert captured["body"]["method"] == "POST"
    assert captured["body"]["headers"]["Authorization"] == "Bearer {{secret}}"
    # The value never appears in the request the SDK builds (placeholder only).
    assert "{{secret}}" in captured["body"]["headers"]["Authorization"]


def test_call_rejects_placeholder_in_url() -> None:
    with pytest.raises(ValueError, match="must not appear in the URL"):
        make_client(lambda r: httpx.Response(404)).call("ODOO", url="https://x/{{secret}}")


def test_typed_call_builds_host_and_auth() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"status": 200, "body": "{}", "projected": True})

    make_client(handler).openai_call("ODOO", "/v1/models")
    assert captured["body"]["url"] == "https://api.openai.com/v1/models"
    assert captured["body"]["headers"]["Authorization"] == "Bearer {{secret}}"


def test_open_session_then_session_call() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/workspaces/ws-1/secrets/by-name/ODOO/proxy-session":
            return httpx.Response(201, json={"session_id": "psess_x", "expires_at": "2026-07-15T00:05:00Z"})
        if request.url.path == "/v1/workspaces/ws-1/proxy-sessions/psess_x/requests":
            return httpx.Response(200, json={"status": 200, "body": '{"page":2}', "projected": True})
        return httpx.Response(404, text=request.url.path)

    client = make_client(handler)
    sess = client.open_proxy_session("ODOO")
    assert isinstance(sess, ProxySession) and sess.session_id == "psess_x"
    resp = client.session_call(sess.session_id, url="https://api.example.com/v1/page?cursor=2")
    assert resp.status == 200 and "page" in resp.body


def test_close_session_deletes() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["path"] = request.url.path
        return httpx.Response(204)

    make_client(handler).close_proxy_session("psess_x")
    assert seen["method"] == "DELETE"
    assert seen["path"] == "/v1/workspaces/ws-1/proxy-sessions/psess_x"


def test_put_and_list_proxy_targets() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/workspaces/ws-1/secrets":
            return httpx.Response(200, json={"secrets": [SECRET_PAYLOAD]})
        if request.url.path == "/v1/workspaces/ws-1/secrets/sec-123/proxy-targets":
            if request.method == "PUT":
                body = json.loads(request.content)
                return httpx.Response(200, json=body)
            return httpx.Response(200, json={"targets": [
                {"host": "api.example.com", "methods": ["GET"], "path_prefixes": ["/v1/"], "response_mode": "projection"}
            ]})
        return httpx.Response(404, text=request.url.path)

    client = make_client(handler)
    saved = client.put_proxy_target("ODOO", ProxyTarget(
        host="api.example.com", methods=["GET"], path_prefixes=["/v1/"], response_fields=["id"]))
    assert saved.host == "api.example.com"
    targets = client.list_proxy_targets("ODOO")
    assert len(targets) == 1 and targets[0].host == "api.example.com"
