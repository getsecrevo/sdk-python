from __future__ import annotations

import json
from typing import Callable

import httpx
import pytest

from secrevo_sdk.client import SecrevoClient

SECRET_PAYLOAD = {
    "workspace_id": "ws-1",
    "secret_id": "sec-123",
    "name": "SUNAT_SOL",
    "description": "",
    "regeneration_instructions": "",
    "status": "active",
    "updated_at": "2026-08-10T02:00:00Z",
}


def make_client(handler: Callable[[httpx.Request], httpx.Response]) -> SecrevoClient:
    return SecrevoClient(
        base_url="https://api.secrevo.local",
        workspace_id="ws-1",
        token="test-token",
        transport=httpx.MockTransport(handler),
    )


def capturing_handler(seen: dict, status: int = 204, body: str = "") -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/workspaces/ws-1/secrets":
            return httpx.Response(200, json={"secrets": [SECRET_PAYLOAD]})
        if request.url.path == "/v1/workspaces/ws-1/secrets/sec-123/value":
            seen["method"] = request.method
            seen["body"] = json.loads(request.content) if request.content else None
            return httpx.Response(status, text=body)
        return httpx.Response(404, text=request.url.path)

    return handler


def test_set_fields_sends_the_whole_bundle() -> None:
    seen: dict = {}
    make_client(capturing_handler(seen)).set_fields(
        "SUNAT_SOL", {"usuario": "u", "clave": "c", "ruc": "20600000001"}
    )
    assert seen["method"] == "PUT"
    assert seen["body"] == {"fields": {"usuario": "u", "clave": "c", "ruc": "20600000001"}}


def test_set_value_is_unchanged_for_a_scalar_secret() -> None:
    seen: dict = {}
    make_client(capturing_handler(seen)).set_value("SUNAT_SOL", "sk-live-abc")
    assert seen["method"] == "PUT"
    assert seen["body"] == {"value": "sk-live-abc"}


def test_values_are_never_trimmed() -> None:
    """A password may legitimately begin or end with a space. Silently trimming
    one stores a credential that does not authenticate while looking exactly
    like one that should — the single worst failure mode for a secret store."""
    seen: dict = {}
    client = make_client(capturing_handler(seen))

    client.set_value("SUNAT_SOL", "  spaced-secret  ")
    assert seen["body"] == {"value": "  spaced-secret  "}

    client.set_fields("SUNAT_SOL", {"clave": " leading", "usuario": "trailing "})
    assert seen["body"] == {"fields": {"clave": " leading", "usuario": "trailing "}}


def test_field_names_are_validated_before_the_round_trip() -> None:
    seen: dict = {}
    client = make_client(capturing_handler(seen))
    for bad in [{"Clave": "c"}, {"1clave": "c"}, {"mi-campo": "c"}, {"": "c"}]:
        with pytest.raises(ValueError) as excinfo:
            client.set_fields("SUNAT_SOL", bad)
        # The message names the offending field so the caller does not have to
        # guess which of several was rejected.
        assert next(iter(bad)) in str(excinfo.value) or "field name" in str(excinfo.value)
    assert "body" not in seen, "an invalid bundle must never reach the network"


def test_empty_field_value_is_refused() -> None:
    client = make_client(capturing_handler({}))
    with pytest.raises(ValueError, match="clave"):
        client.set_fields("SUNAT_SOL", {"usuario": "u", "clave": ""})


def test_empty_bundle_points_at_set_value() -> None:
    client = make_client(capturing_handler({}))
    with pytest.raises(ValueError, match="set_value"):
        client.set_fields("SUNAT_SOL", {})


def test_too_many_fields_is_refused_client_side() -> None:
    client = make_client(capturing_handler({}))
    with pytest.raises(ValueError, match="at most 32"):
        client.set_fields("SUNAT_SOL", {f"f{i}": "v" for i in range(33)})


def test_scalar_write_to_a_bundle_surfaces_the_api_refusal() -> None:
    """The API refuses it (KV v2 replaces the whole map, so a scalar write would
    drop every sibling field). The SDK must surface that rather than swallow it."""
    from secrevo_sdk.exceptions import SecrevoAPIError

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/workspaces/ws-1/secrets":
            return httpx.Response(200, json={"secrets": [SECRET_PAYLOAD]})
        return httpx.Response(
            409,
            json={
                "error": "multi_field_secret",
                "message": 'secret "SUNAT_SOL" stores named fields: clave, usuario',
            },
        )

    with pytest.raises(SecrevoAPIError) as excinfo:
        make_client(handler).set_value("SUNAT_SOL", "oops")
    assert excinfo.value.status_code == 409
    assert "multi_field_secret" in (excinfo.value.response_body or "")


@pytest.mark.asyncio
async def test_async_client_has_parity() -> None:
    """The async client mirrors the sync surface; a write method missing there
    is a silent fork in the SDK's contract."""
    from secrevo_sdk.async_client import AsyncSecrevoClient

    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/workspaces/ws-1/secrets":
            return httpx.Response(200, json={"secrets": [SECRET_PAYLOAD]})
        if request.url.path == "/v1/workspaces/ws-1/secrets/sec-123/value":
            seen["method"] = request.method
            seen["body"] = json.loads(request.content)
            return httpx.Response(204)
        return httpx.Response(404, text=request.url.path)

    async with AsyncSecrevoClient(
        base_url="https://api.secrevo.local",
        workspace_id="ws-1",
        token="test-token",
        transport=httpx.MockTransport(handler),
    ) as client:
        await client.set_fields("SUNAT_SOL", {"usuario": "u", "clave": " c "})
        assert seen["body"] == {"fields": {"usuario": "u", "clave": " c "}}
        with pytest.raises(ValueError):
            await client.set_fields("SUNAT_SOL", {"Bad": "x"})
