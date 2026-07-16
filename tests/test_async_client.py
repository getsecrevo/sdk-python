from __future__ import annotations

from typing import Awaitable, Callable

import httpx
import pytest

from secrevo_sdk import AsyncSecrevoClient
from secrevo_sdk.exceptions import (
    AgentRevokedError,
    IntegrationNotInstalledError,
    RateLimitedError,
    SecretNotFoundError,
    SecrevoAPIError,
)


SECRET_PAYLOAD = {
    "workspace_id": "ws-1",
    "secret_id": "sec-123",
    "name": "api-key",
    "description": "OpenAI API key",
    "regeneration_instructions": "Rotate in provider console",
    "status": "active",
    "updated_at": "2026-05-06T02:00:00Z",
}


def build_handler(
    *, list_secrets: list[dict] | None = None, value: str | None = None
) -> Callable[[httpx.Request], httpx.Response]:
    secrets = [SECRET_PAYLOAD] if list_secrets is None else list_secrets

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/v1/workspaces/ws-1/secrets":
            return httpx.Response(200, json={"secrets": secrets})
        if path == "/v1/workspaces/ws-1/secrets/sec-123":
            return httpx.Response(200, json=SECRET_PAYLOAD)
        if path in (
            "/v1/workspaces/ws-1/secrets/sec-123/value",
            "/v1/workspaces/ws-1/secrets/by-name/api-key/value",
        ):
            if value is None:
                return httpx.Response(403, text="forbidden")
            return httpx.Response(
                200,
                json={
                    "workspace_id": "ws-1",
                    "secret_id": "sec-123",
                    "value": value,
                },
            )
        return httpx.Response(404, text=f"unexpected: {request.method} {path}")

    return handler


def make_client(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    max_retries: int = 3,
    sleep: Callable[[float], Awaitable[None]] | None = None,
) -> AsyncSecrevoClient:
    kwargs: dict = {
        "base_url": "https://api.secrevo.local",
        "workspace_id": "ws-1",
        "token": "test-token",
        "transport": httpx.MockTransport(handler),
        "max_retries": max_retries,
    }
    if sleep is not None:
        kwargs["sleep"] = sleep
    return AsyncSecrevoClient(**kwargs)


@pytest.mark.asyncio
async def test_async_list_then_get_flow() -> None:
    requests: list[httpx.Request] = []
    base = build_handler()

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return base(request)

    async with make_client(handler) as client:
        secret = await client.get("api-key")

    assert secret.secret_id == "sec-123"
    assert [r.url.path for r in requests] == [
        "/v1/workspaces/ws-1/secrets",
        "/v1/workspaces/ws-1/secrets/sec-123",
    ]


@pytest.mark.asyncio
async def test_async_reveal_value_returns_plaintext() -> None:
    async with make_client(build_handler(value="sk-live-abc")) as client:
        revealed = await client.reveal_value("api-key")
    assert revealed.value == "sk-live-abc"
    assert revealed.secret.secret_id == "sec-123"


@pytest.mark.asyncio
async def test_async_missing_secret_lists_available_names() -> None:
    other = {**SECRET_PAYLOAD, "secret_id": "sec-999", "name": "stripe-live"}
    async with make_client(build_handler(list_secrets=[SECRET_PAYLOAD, other])) as client:
        with pytest.raises(SecretNotFoundError) as info:
            await client.get("missing-name")

    err = info.value
    assert err.available == ["api-key", "stripe-live"]


@pytest.mark.asyncio
async def test_async_agent_revoked_response_raises_distinct_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="agent token has been revoked")

    async with make_client(handler) as client:
        with pytest.raises(AgentRevokedError):
            await client.list_secrets(refresh=True)


@pytest.mark.asyncio
async def test_async_rate_limit_surfaces_retry_after_seconds() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="slow down", headers={"Retry-After": "9"})

    async with make_client(handler, max_retries=0) as client:
        with pytest.raises(RateLimitedError) as info:
            await client.list_secrets(refresh=True)
    assert info.value.retry_after_seconds == pytest.approx(9.0)


@pytest.mark.asyncio
async def test_async_retry_succeeds_after_transient_5xx() -> None:
    responses = iter(
        [
            httpx.Response(503, text="upstream down"),
            httpx.Response(200, json={"secrets": [SECRET_PAYLOAD]}),
        ]
    )
    sleep_calls: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleep_calls.append(seconds)

    def handler(request: httpx.Request) -> httpx.Response:
        return next(responses)

    async with make_client(handler, max_retries=2, sleep=fake_sleep) as client:
        result = await client.list_secrets(refresh=True)

    assert len(result) == 1
    assert len(sleep_calls) == 1


@pytest.mark.asyncio
async def test_async_retry_honors_retry_after_on_429() -> None:
    responses = iter(
        [
            httpx.Response(429, text="slow down", headers={"Retry-After": "4"}),
            httpx.Response(200, json={"secrets": [SECRET_PAYLOAD]}),
        ]
    )
    sleep_calls: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleep_calls.append(seconds)

    def handler(request: httpx.Request) -> httpx.Response:
        return next(responses)

    async with make_client(handler, max_retries=2, sleep=fake_sleep) as client:
        await client.list_secrets(refresh=True)

    assert sleep_calls == [pytest.approx(4.0)]


@pytest.mark.asyncio
async def test_async_retry_on_transport_error() -> None:
    attempts = {"n": 0}
    sleep_calls: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleep_calls.append(seconds)

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise httpx.ConnectError("refused")
        return httpx.Response(200, json={"secrets": [SECRET_PAYLOAD]})

    async with make_client(handler, max_retries=2, sleep=fake_sleep) as client:
        result = await client.list_secrets(refresh=True)

    assert len(result) == 1
    assert len(sleep_calls) == 1


@pytest.mark.asyncio
async def test_async_from_env_reads_standard_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECREVO_API_BASE_URL", "https://api.secrevo.local")
    monkeypatch.setenv("SECREVO_WORKSPACE_ID", "ws-1")
    monkeypatch.setenv("SECREVO_API_TOKEN", "agt_xyz")

    client = AsyncSecrevoClient.from_env(transport=httpx.MockTransport(build_handler()))
    try:
        secrets = await client.list_secrets()
        assert secrets[0].name == "api-key"
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_async_integration_helpers_raise_with_clear_install_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import importlib

    real_import_module = importlib.import_module

    def fake_import_module(name: str, *args, **kwargs):
        if name in {"openai", "anthropic", "stripe", "boto3", "github"}:
            raise ImportError(f"forced miss for {name}")
        return real_import_module(name, *args, **kwargs)

    monkeypatch.setattr(importlib, "import_module", fake_import_module)

    async with make_client(build_handler(value="sk-live-123")) as client:
        with pytest.raises(IntegrationNotInstalledError) as info:
            await client.openai_for("api-key")
        assert "pip install openai" in str(info.value)

        with pytest.raises(IntegrationNotInstalledError):
            await client.anthropic_for("api-key")
        with pytest.raises(IntegrationNotInstalledError):
            await client.stripe_for("api-key")
        with pytest.raises(IntegrationNotInstalledError):
            await client.aws_session_for(
                access_key_secret="api-key",
                secret_key_secret="api-key",
            )
        with pytest.raises(IntegrationNotInstalledError) as gh_info:
            await client.github_for("api-key")
        assert "pip install PyGithub" in str(gh_info.value)


@pytest.mark.asyncio
async def test_async_call_and_session_flow() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        p = request.url.path
        if p == "/v1/workspaces/ws-1/secrets/by-name/ODOO/proxy":
            return httpx.Response(200, json={"status": 200, "body": "{}", "projected": True})
        if p == "/v1/workspaces/ws-1/secrets/by-name/ODOO/proxy-session":
            return httpx.Response(201, json={"session_id": "psess_a", "expires_at": "2026-07-15T00:05:00Z"})
        if p == "/v1/workspaces/ws-1/proxy-sessions/psess_a/requests":
            return httpx.Response(200, json={"status": 200, "body": '{"ok":1}', "projected": True})
        if p == "/v1/workspaces/ws-1/proxy-sessions/psess_a":
            return httpx.Response(204)
        return httpx.Response(404, text=p)

    client = make_client(handler)
    r = await client.call("ODOO", url="https://api.example.com/v1/x", method="POST", headers={"H": "{{secret}}"})
    assert r.status == 200
    sess = await client.open_proxy_session("ODOO")
    assert sess.session_id == "psess_a"
    sr = await client.session_call(sess.session_id, url="https://api.example.com/v1/y")
    assert sr.status == 200 and "ok" in sr.body
    await client.close_proxy_session(sess.session_id)
    await client.aclose()
