from __future__ import annotations

import json
from typing import Callable

import httpx
import pytest

from secrevo_sdk import Cred, CredScope
from secrevo_sdk.async_client import AsyncSecrevoClient
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

CRED_PAYLOAD = {
    "provider": "aws_sts",
    "access_key_id": "ASIAEXAMPLE",
    "secret_access_key": "secretpart",
    "session_token": "sessiontok",
    "expiration": "2030-01-01T00:00:00Z",
    "ttl_seconds": 900,
}


def make_client(handler: Callable[[httpx.Request], httpx.Response]) -> SecrevoClient:
    return SecrevoClient(
        base_url="https://api.secrevo.local",
        workspace_id="ws-1",
        token="test-token",
        transport=httpx.MockTransport(handler),
    )


def test_mint_creds_posts_to_creds_and_returns_cred() -> None:
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/workspaces/ws-1/secrets/by-name/AMBER_ODOO_AWS/creds":
            captured["body"] = json.loads(request.content)
            return httpx.Response(200, json=CRED_PAYLOAD)
        return httpx.Response(404, text=request.url.path)

    cred = make_client(handler).mint_creds("AMBER_ODOO_AWS", ttl_seconds=900)
    assert isinstance(cred, Cred)
    assert cred.provider == "aws_sts" and cred.access_key_id == "ASIAEXAMPLE"
    assert cred.ttl_seconds == 900
    assert captured["body"]["ttl_seconds"] == 900


def test_cred_repr_redacts_live_material() -> None:
    cred = Cred.from_payload(CRED_PAYLOAD)
    text = repr(cred)
    assert "secretpart" not in text and "sessiontok" not in text and "ASIAEXAMPLE" not in text
    assert "aws_sts" in text  # non-secret provider is fine to show


def test_put_and_get_cred_scope() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/workspaces/ws-1/secrets":
            return httpx.Response(200, json={"secrets": [SECRET_PAYLOAD]})
        if request.url.path == "/v1/workspaces/ws-1/secrets/sec-123/cred-scope":
            if request.method == "PUT":
                return httpx.Response(200, json=json.loads(request.content))
            return httpx.Response(200, json={
                "provider": "aws_sts",
                "config": {"role_arn": "arn:aws:iam::007761758105:role/x"},
                "max_ttl_seconds": 900,
            })
        return httpx.Response(404, text=request.url.path)

    client = make_client(handler)
    saved = client.put_cred_scope("AMBER_ODOO_AWS", CredScope(
        provider="aws_sts", config={"role_arn": "arn:aws:iam::007761758105:role/x"}, max_ttl_seconds=900))
    assert saved.provider == "aws_sts" and saved.config["role_arn"].endswith("role/x")
    got = client.get_cred_scope("AMBER_ODOO_AWS")
    assert got.provider == "aws_sts" and got.max_ttl_seconds == 900


def test_remove_cred_scope_deletes() -> None:
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/workspaces/ws-1/secrets":
            return httpx.Response(200, json={"secrets": [SECRET_PAYLOAD]})
        seen["method"], seen["path"] = request.method, request.url.path
        return httpx.Response(204)

    make_client(handler).remove_cred_scope("AMBER_ODOO_AWS")
    assert seen["method"] == "DELETE"
    assert seen["path"] == "/v1/workspaces/ws-1/secrets/sec-123/cred-scope"


@pytest.mark.asyncio
async def test_async_mint_creds() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/workspaces/ws-1/secrets/by-name/AMBER_ODOO_AWS/creds":
            return httpx.Response(200, json=CRED_PAYLOAD)
        return httpx.Response(404, text=request.url.path)

    client = AsyncSecrevoClient(
        base_url="https://api.secrevo.local",
        workspace_id="ws-1",
        token="test-token",
        transport=httpx.MockTransport(handler),
    )
    try:
        cred = await client.mint_creds("AMBER_ODOO_AWS")
        assert cred.provider == "aws_sts" and cred.access_key_id == "ASIAEXAMPLE"
    finally:
        await client.aclose()
