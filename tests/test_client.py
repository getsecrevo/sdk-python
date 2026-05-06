from __future__ import annotations

import json

import httpx
import pytest

from secrevo_sdk.client import SecrevoClient, normalize_access_mode
from secrevo_sdk.exceptions import SecrevoAPIError, SecretNotFoundError


def test_normalize_access_mode_aliases() -> None:
    assert normalize_access_mode(None) == "standard"
    assert normalize_access_mode("default") == "standard"
    assert normalize_access_mode("context") == "with_context"
    assert normalize_access_mode("with-context") == "with_context"
    assert normalize_access_mode("agent") == "for_agent"
    assert normalize_access_mode("for_agent") == "for_agent"


def test_get_uses_list_then_detail_request() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "GET" and request.url.path == "/v1/workspaces/ws-1/secrets":
            assert request.headers["Authorization"] == "Bearer test-token"
            assert request.headers["Accept"] == "application/json"
            return httpx.Response(
                200,
                json={
                    "secrets": [
                        {
                            "workspace_id": "ws-1",
                            "secret_id": "sec-123",
                            "name": "api-key",
                            "description": "OpenAI API key",
                            "regeneration_instructions": "Rotate in provider console",
                            "status": "active",
                            "updated_at": "2026-05-06T02:00:00Z",
                        }
                    ]
                },
            )
        if request.method == "GET" and request.url.path == "/v1/workspaces/ws-1/secrets/sec-123":
            assert request.headers["Authorization"] == "Bearer test-token"
            assert request.headers["Accept"] == "application/json"
            return httpx.Response(
                200,
                json={
                    "workspace_id": "ws-1",
                    "secret_id": "sec-123",
                    "name": "api-key",
                    "description": "OpenAI API key",
                    "regeneration_instructions": "Rotate in provider console",
                    "status": "active",
                    "updated_at": "2026-05-06T02:00:00Z",
                },
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    client = SecrevoClient(
        base_url="https://api.secrevo.local",
        workspace_id="ws-1",
        token="test-token",
        transport=httpx.MockTransport(handler),
    )

    secret = client.get("api-key")

    assert secret.secret_id == "sec-123"
    assert secret.name == "api-key"
    assert len(requests) == 2
    assert requests[0].url.path == "/v1/workspaces/ws-1/secrets"
    assert requests[1].url.path == "/v1/workspaces/ws-1/secrets/sec-123"


@pytest.mark.parametrize(
    ("method_name", "expected_mode"),
    [
        ("get_with_context", "with_context"),
        ("get_for_agent", "for_agent"),
    ],
)
def test_secret_access_views_normalize_mode(method_name: str, expected_mode: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/workspaces/ws-1/secrets":
            return httpx.Response(
                200,
                json={
                    "secrets": [
                        {
                            "workspace_id": "ws-1",
                            "secret_id": "sec-123",
                            "name": "api-key",
                            "description": "OpenAI API key",
                            "regeneration_instructions": "Rotate in provider console",
                            "status": "active",
                            "updated_at": "2026-05-06T02:00:00Z",
                        }
                    ]
                },
            )
        if request.url.path == "/v1/workspaces/ws-1/secrets/sec-123":
            return httpx.Response(
                200,
                json={
                    "workspace_id": "ws-1",
                    "secret_id": "sec-123",
                    "name": "api-key",
                    "description": "OpenAI API key",
                    "regeneration_instructions": "Rotate in provider console",
                    "status": "active",
                    "updated_at": "2026-05-06T02:00:00Z",
                },
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    client = SecrevoClient(
        base_url="https://api.secrevo.local",
        workspace_id="ws-1",
        token="test-token",
        transport=httpx.MockTransport(handler),
    )

    access = getattr(client, method_name)("api-key")

    assert access.access_mode == expected_mode
    assert access.secret.name == "api-key"
    assert access.context["workspace_id"] == "ws-1"
    assert access.context["secret_name"] == "api-key"
    assert access.context["access_mode"] == expected_mode


def test_openai_stub_is_explicitly_not_implemented() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/workspaces/ws-1/secrets":
            return httpx.Response(
                200,
                json={
                    "secrets": [
                        {
                            "workspace_id": "ws-1",
                            "secret_id": "sec-123",
                            "name": "api-key",
                            "description": "OpenAI API key",
                            "regeneration_instructions": "Rotate in provider console",
                            "status": "active",
                            "updated_at": "2026-05-06T02:00:00Z",
                        }
                    ]
                },
            )
        if request.url.path == "/v1/workspaces/ws-1/secrets/sec-123":
            return httpx.Response(
                200,
                json={
                    "workspace_id": "ws-1",
                    "secret_id": "sec-123",
                    "name": "api-key",
                    "description": "OpenAI API key",
                    "regeneration_instructions": "Rotate in provider console",
                    "status": "active",
                    "updated_at": "2026-05-06T02:00:00Z",
                },
            )
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    client = SecrevoClient(
        base_url="https://api.secrevo.local",
        workspace_id="ws-1",
        token="test-token",
        transport=httpx.MockTransport(handler),
    )

    stub = client.openai_for("api-key")

    assert stub.provider == "openai"
    assert stub.access_mode == "for_agent"
    assert stub.secret.secret_id == "sec-123"
    with pytest.raises(NotImplementedError):
        stub.as_client_kwargs()


def test_missing_secret_raises_clear_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/workspaces/ws-1/secrets":
            return httpx.Response(200, json={"secrets": []})
        raise AssertionError(f"unexpected request: {request.method} {request.url}")

    client = SecrevoClient(
        base_url="https://api.secrevo.local",
        workspace_id="ws-1",
        token="test-token",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(SecretNotFoundError):
        client.get("missing")

