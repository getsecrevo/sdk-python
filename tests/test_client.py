from __future__ import annotations

from typing import Callable

import httpx
import pytest

from secrevo_sdk.client import SecrevoClient, normalize_access_mode
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
    """Construct a fake handler that responds to the standard list/detail/value
    paths with the provided fixtures. Other paths return 404.
    """
    secrets = [SECRET_PAYLOAD] if list_secrets is None else list_secrets

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/v1/workspaces/ws-1/secrets":
            return httpx.Response(200, json={"secrets": secrets})
        if path == "/v1/workspaces/ws-1/secrets/sec-123":
            return httpx.Response(200, json=SECRET_PAYLOAD)
        # reveal_value resolves + reveals in one call against the by-name value
        # endpoint (so a per-secret grant suffices). The by-id value path is kept
        # for any direct callers.
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


def make_client(handler: Callable[[httpx.Request], httpx.Response]) -> SecrevoClient:
    return SecrevoClient(
        base_url="https://api.secrevo.local",
        workspace_id="ws-1",
        token="test-token",
        transport=httpx.MockTransport(handler),
    )


def test_from_env_reads_standard_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECREVO_API_BASE_URL", "https://api.secrevo.local")
    monkeypatch.setenv("SECREVO_WORKSPACE_ID", "ws-1")
    monkeypatch.setenv("SECREVO_API_TOKEN", "agt_xyz")

    client = SecrevoClient.from_env(transport=httpx.MockTransport(build_handler()))

    assert client.workspace_id == "ws-1"
    # Hit the API to confirm the constructed client is functional.
    secrets = client.list_secrets()
    assert secrets[0].name == "api-key"


def test_from_env_raises_on_missing_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECREVO_API_BASE_URL", "https://api.secrevo.local")
    monkeypatch.setenv("SECREVO_WORKSPACE_ID", "ws-1")
    monkeypatch.delenv("SECREVO_API_TOKEN", raising=False)

    with pytest.raises(ValueError) as info:
        SecrevoClient.from_env()
    assert "SECREVO_API_TOKEN" in str(info.value)
    assert "secrevo login" in str(info.value)


def test_from_env_raises_on_empty_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECREVO_API_BASE_URL", "https://api.secrevo.local")
    monkeypatch.setenv("SECREVO_WORKSPACE_ID", "   ")
    monkeypatch.setenv("SECREVO_API_TOKEN", "agt_xyz")

    with pytest.raises(ValueError) as info:
        SecrevoClient.from_env()
    assert "SECREVO_WORKSPACE_ID" in str(info.value)


def test_normalize_access_mode_aliases() -> None:
    assert normalize_access_mode(None) == "standard"
    assert normalize_access_mode("default") == "standard"
    assert normalize_access_mode("context") == "with_context"
    assert normalize_access_mode("with-context") == "with_context"
    assert normalize_access_mode("agent") == "for_agent"
    assert normalize_access_mode("for_agent") == "for_agent"


def test_get_uses_list_then_detail_request() -> None:
    requests: list[httpx.Request] = []
    base = build_handler()

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return base(request)

    client = make_client(handler)
    secret = client.get("api-key")

    assert secret.secret_id == "sec-123"
    assert secret.name == "api-key"
    assert len(requests) == 2
    assert requests[0].url.path == "/v1/workspaces/ws-1/secrets"
    assert requests[1].url.path == "/v1/workspaces/ws-1/secrets/sec-123"


def test_list_secrets_caches_until_refresh() -> None:
    requests: list[httpx.Request] = []
    base = build_handler()

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return base(request)

    client = make_client(handler)
    first = client.list_secrets()
    second = client.list_secrets()
    third = client.list_secrets(refresh=True)

    assert first == second == third
    list_calls = [r for r in requests if r.url.path == "/v1/workspaces/ws-1/secrets"]
    assert len(list_calls) == 2  # one for the first call, one for refresh=True


@pytest.mark.parametrize(
    ("method_name", "expected_mode"),
    [
        ("get_with_context", "with_context"),
        ("get_for_agent", "for_agent"),
    ],
)
def test_secret_access_views_normalize_mode(method_name: str, expected_mode: str) -> None:
    client = make_client(build_handler())

    access = getattr(client, method_name)("api-key")

    assert access.access_mode == expected_mode
    assert access.secret.name == "api-key"
    assert access.context["workspace_id"] == "ws-1"
    assert access.context["secret_name"] == "api-key"
    assert access.context["access_mode"] == expected_mode


def test_reveal_value_returns_plaintext() -> None:
    client = make_client(build_handler(value="sk-live-123"))

    revealed = client.reveal_value("api-key")

    assert revealed.value == "sk-live-123"
    assert revealed.secret.secret_id == "sec-123"


def test_reveal_value_works_without_workspace_list_access() -> None:
    """A caller holding only a per-secret grant (the team-sharing model) can
    reveal a shared secret: reveal_value must use the by-name value endpoint and
    never the list endpoint, which requires secret.read@workspace."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        seen.append(path)
        if path == "/v1/workspaces/ws-1/secrets":
            return httpx.Response(403, text="forbidden")  # no workspace read
        if path == "/v1/workspaces/ws-1/secrets/by-name/api-key/value":
            return httpx.Response(
                200,
                json={"workspace_id": "ws-1", "secret_id": "sec-123", "value": "sk-shared"},
            )
        return httpx.Response(404, text=f"unexpected: {request.method} {path}")

    revealed = make_client(handler).reveal_value("api-key")

    assert revealed.value == "sk-shared"
    assert revealed.secret.secret_id == "sec-123"
    assert "/v1/workspaces/ws-1/secrets" not in seen  # never listed


def test_missing_secret_lists_available_names() -> None:
    other = {**SECRET_PAYLOAD, "secret_id": "sec-999", "name": "stripe-live"}
    client = make_client(build_handler(list_secrets=[SECRET_PAYLOAD, other]))

    with pytest.raises(SecretNotFoundError) as info:
        client.get("missing-name")

    err = info.value
    assert err.workspace_id == "ws-1"
    assert err.available == ["api-key", "stripe-live"]
    assert "api-key" in str(err)
    assert "stripe-live" in str(err)


def test_agent_revoked_response_raises_distinct_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="agent token has been revoked")

    client = make_client(handler)

    with pytest.raises(AgentRevokedError):
        client.list_secrets(refresh=True)


def test_rate_limit_surfaces_retry_after_seconds() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="slow down", headers={"Retry-After": "12"})

    # Disable retries so the 429 surfaces immediately.
    client = SecrevoClient(
        base_url="https://api.secrevo.local",
        workspace_id="ws-1",
        token="test-token",
        transport=httpx.MockTransport(handler),
        max_retries=0,
    )

    with pytest.raises(RateLimitedError) as info:
        client.list_secrets(refresh=True)
    assert info.value.retry_after_seconds == pytest.approx(12.0)


def test_retry_succeeds_after_transient_5xx() -> None:
    """A 503 once, then 200 should yield a successful list without raising."""
    responses = iter(
        [
            httpx.Response(503, text="upstream down"),
            httpx.Response(200, json={"secrets": [SECRET_PAYLOAD]}),
        ]
    )
    sleep_calls: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        return next(responses)

    client = SecrevoClient(
        base_url="https://api.secrevo.local",
        workspace_id="ws-1",
        token="test-token",
        transport=httpx.MockTransport(handler),
        max_retries=2,
        sleep=sleep_calls.append,
    )

    result = client.list_secrets(refresh=True)
    assert len(result) == 1
    assert len(sleep_calls) == 1
    assert sleep_calls[0] >= 0


def test_retry_honors_retry_after_on_429() -> None:
    """The first 429 should sleep for the Retry-After value, not exponential backoff."""
    responses = iter(
        [
            httpx.Response(429, text="slow down", headers={"Retry-After": "7"}),
            httpx.Response(200, json={"secrets": [SECRET_PAYLOAD]}),
        ]
    )
    sleep_calls: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        return next(responses)

    client = SecrevoClient(
        base_url="https://api.secrevo.local",
        workspace_id="ws-1",
        token="test-token",
        transport=httpx.MockTransport(handler),
        max_retries=2,
        retry_backoff_max=30.0,
        sleep=sleep_calls.append,
    )

    client.list_secrets(refresh=True)
    assert sleep_calls == [pytest.approx(7.0)]


def test_retry_exhausts_then_raises_for_persistent_5xx() -> None:
    sleep_calls: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="still down")

    client = SecrevoClient(
        base_url="https://api.secrevo.local",
        workspace_id="ws-1",
        token="test-token",
        transport=httpx.MockTransport(handler),
        max_retries=2,
        sleep=sleep_calls.append,
    )

    with pytest.raises(SecrevoAPIError) as info:
        client.list_secrets(refresh=True)
    assert info.value.status_code == 503
    assert len(sleep_calls) == 2  # 2 retries, then raise


def test_retry_on_transport_error() -> None:
    """Network errors should be retried like 5xx, not surface as raw exceptions."""
    attempts = {"n": 0}
    sleep_calls: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise httpx.ConnectError("connection refused")
        return httpx.Response(200, json={"secrets": [SECRET_PAYLOAD]})

    client = SecrevoClient(
        base_url="https://api.secrevo.local",
        workspace_id="ws-1",
        token="test-token",
        transport=httpx.MockTransport(handler),
        max_retries=2,
        sleep=sleep_calls.append,
    )

    result = client.list_secrets(refresh=True)
    assert len(result) == 1
    assert len(sleep_calls) == 1


def test_generic_5xx_surfaces_status_code() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="upstream down")

    client = make_client(handler)

    with pytest.raises(SecrevoAPIError) as info:
        client.list_secrets(refresh=True)
    assert info.value.status_code == 503


def test_integration_helpers_raise_with_clear_install_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each integration imports its third-party SDK lazily; if it isn't
    installed the SDK should hand the user the exact `pip install` line.
    """
    client = make_client(build_handler(value="sk-live-123"))

    # Force importlib to fail for these names regardless of what's installed
    # locally on the test machine.
    import importlib

    real_import_module = importlib.import_module

    def fake_import_module(name: str, *args, **kwargs):
        if name in {"openai", "anthropic", "stripe", "boto3", "github"}:
            raise ImportError(f"forced miss for {name}")
        return real_import_module(name, *args, **kwargs)

    monkeypatch.setattr(importlib, "import_module", fake_import_module)

    with pytest.raises(IntegrationNotInstalledError) as info:
        client.openai_for("api-key")
    assert "pip install openai" in str(info.value)

    with pytest.raises(IntegrationNotInstalledError):
        client.anthropic_for("api-key")
    with pytest.raises(IntegrationNotInstalledError):
        client.stripe_for("api-key")
    with pytest.raises(IntegrationNotInstalledError):
        client.aws_session_for(
            access_key_secret="api-key",
            secret_key_secret="api-key",
        )
    with pytest.raises(IntegrationNotInstalledError) as gh_info:
        client.github_for("api-key")
    assert "pip install PyGithub" in str(gh_info.value)
