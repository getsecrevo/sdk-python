"""Tests for the rotation grace-window previous-value read (api#46).

Guardrails:
- Never print revealed values. Assertions are on hashes, lengths, or
  ``bool(value)`` only — never the plaintext.
- Never read cache files for content. Cache-skip behavior is verified
  by file modification time and ``cache.get`` returning ``None``.
"""
from __future__ import annotations

import hashlib
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import httpx
import pytest

from secrevo_sdk.cache import FileCache
from secrevo_sdk.client import SecrevoClient
from secrevo_sdk.exceptions import (
    SecrevoAPIError,
    SecrevoOfflineError,
    SecrevoPreviousValueNotFoundError,
)


SECRET_PAYLOAD = {
    "workspace_id": "ws-1",
    "secret_id": "sec-123",
    "name": "api-key",
    "description": "OpenAI API key",
    "regeneration_instructions": "Rotate in provider console",
    "status": "active",
    "updated_at": "2026-06-02T02:00:00Z",
}

CURRENT_VALUE = "sk-current-" + "x" * 24
PREVIOUS_VALUE = "sk-previous-" + "y" * 24
GRACE_EXPIRES_AT_ISO = "2026-06-02T15:30:00Z"


def _hash(v: str) -> str:
    return hashlib.sha256(v.encode("utf-8")).hexdigest()


def make_handler(
    *,
    previous_value: str | None = PREVIOUS_VALUE,
    grace_header: str | None = GRACE_EXPIRES_AT_ISO,
    requests_seen: list[httpx.Request] | None = None,
) -> Callable[[httpx.Request], httpx.Response]:
    """Build a transport that serves the value endpoint per ``version``.

    - No ``version`` query → current value (200 with CURRENT_VALUE).
    - ``version=previous`` → previous value (200 with PREVIOUS_VALUE),
      including the ``X-Secrevo-Grace-Expires-At`` header. If
      ``previous_value`` is ``None`` returns 404 ``not_found_previous``
      to simulate "no grace window active".
    """

    def handler(request: httpx.Request) -> httpx.Response:
        if requests_seen is not None:
            requests_seen.append(request)
        path = request.url.path
        if path == "/v1/workspaces/ws-1/secrets":
            return httpx.Response(200, json={"secrets": [SECRET_PAYLOAD]})
        if path == "/v1/workspaces/ws-1/secrets/sec-123":
            return httpx.Response(200, json=SECRET_PAYLOAD)
        if path == "/v1/workspaces/ws-1/secrets/sec-123/value":
            version = request.url.params.get("version")
            if version == "previous":
                if previous_value is None:
                    return httpx.Response(
                        404,
                        json={
                            "error": "not_found_previous",
                            "message": "no previous value within grace window",
                        },
                    )
                headers = {}
                if grace_header is not None:
                    headers["X-Secrevo-Grace-Expires-At"] = grace_header
                return httpx.Response(
                    200,
                    headers=headers,
                    json={
                        "workspace_id": "ws-1",
                        "secret_id": "sec-123",
                        "value": previous_value,
                    },
                )
            return httpx.Response(
                200,
                json={
                    "workspace_id": "ws-1",
                    "secret_id": "sec-123",
                    "value": CURRENT_VALUE,
                },
            )
        return httpx.Response(404, text=f"unexpected: {request.method} {path}")

    return handler


def make_client(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    cache: FileCache | None = None,
) -> SecrevoClient:
    return SecrevoClient(
        base_url="https://api.secrevo.local",
        workspace_id="ws-1",
        token="test-token",
        transport=httpx.MockTransport(handler),
        cache=cache,
        max_retries=0,
        sleep=lambda _: None,
    )


def test_default_version_is_current_no_query_param_no_grace_field() -> None:
    """Default reveal_value() must hit the unaffected current path:
    no ``?version=`` query string, no ``grace_expires_at`` on the result.
    """
    seen: list[httpx.Request] = []
    client = make_client(make_handler(requests_seen=seen))

    revealed = client.reveal_value("api-key")

    assert bool(revealed.value) is True
    assert _hash(revealed.value) == _hash(CURRENT_VALUE)
    assert revealed.grace_expires_at is None
    assert revealed.degraded is False

    value_calls = [r for r in seen if r.url.path.endswith("/value")]
    assert len(value_calls) == 1
    assert "version" not in value_calls[0].url.params


def test_previous_version_happy_path_returns_grace_header() -> None:
    seen: list[httpx.Request] = []
    client = make_client(make_handler(requests_seen=seen))

    revealed = client.reveal_value("api-key", version="previous")

    assert bool(revealed.value) is True
    assert _hash(revealed.value) == _hash(PREVIOUS_VALUE)
    assert _hash(revealed.value) != _hash(CURRENT_VALUE)

    assert revealed.grace_expires_at is not None
    assert isinstance(revealed.grace_expires_at, datetime)
    assert revealed.grace_expires_at.tzinfo is not None
    assert revealed.grace_expires_at.utcoffset() == timezone.utc.utcoffset(None)
    assert revealed.grace_expires_at == datetime(
        2026, 6, 2, 15, 30, 0, tzinfo=timezone.utc
    )

    value_calls = [r for r in seen if r.url.path.endswith("/value")]
    assert len(value_calls) == 1
    assert value_calls[0].url.params.get("version") == "previous"


def test_previous_version_404_raises_distinct_exception() -> None:
    client = make_client(make_handler(previous_value=None))

    with pytest.raises(SecrevoPreviousValueNotFoundError) as info:
        client.reveal_value("api-key", version="previous")

    assert "api-key" in str(info.value)
    assert "grace" in str(info.value).lower()
    # Distinctness: a previous-value 404 must NOT surface as a plain
    # SecrevoAPIError to callers branching on type.
    assert isinstance(info.value, SecrevoAPIError)  # still a subclass
    assert type(info.value).__name__ == "SecrevoPreviousValueNotFoundError"


def test_previous_version_does_not_read_or_write_cache(tmp_path: Path) -> None:
    """Cache contract: previous reads bypass cache for both read AND write.

    Strategy: prime the cache with a current-value read, snapshot the
    cache file's mtime, then call with ``version="previous"`` and
    verify (a) the result is the previous value (so cache wasn't read
    in lieu of the API), (b) the cache file's mtime is unchanged (so
    cache wasn't written).
    """
    key = os.urandom(32)
    cache = FileCache(directory=tmp_path, encryption_key=key)
    client = make_client(make_handler(), cache=cache)

    # Prime the cache with a current read.
    primed = client.reveal_value("api-key")
    assert _hash(primed.value) == _hash(CURRENT_VALUE)

    # Identify the encrypted cache file and snapshot its mtime.
    cache_files = [p for p in tmp_path.iterdir() if p.is_file() and not p.name.endswith(".lock")]
    assert len(cache_files) == 1, f"expected 1 cache file, got {len(cache_files)}"
    cache_file = cache_files[0]
    mtime_before = cache_file.stat().st_mtime_ns

    # Sleep enough that any rewrite would show up on the mtime (Windows
    # FAT/NTFS resolution is sub-millisecond, but be defensive).
    time.sleep(0.05)

    # Previous-value read: cache MUST be skipped on both read and write.
    previous = client.reveal_value("api-key", version="previous")
    assert _hash(previous.value) == _hash(PREVIOUS_VALUE)
    assert previous.grace_expires_at is not None

    mtime_after = cache_file.stat().st_mtime_ns
    assert mtime_after == mtime_before, (
        "cache file was rewritten during a previous-value read — "
        "contract violation"
    )

    # And the cache, when read directly, still holds the CURRENT value
    # (not the previous one).
    cached = cache.get("ws-1:api-key")
    assert cached is not None
    assert _hash(cached.value) == _hash(CURRENT_VALUE)
    assert _hash(cached.value) != _hash(PREVIOUS_VALUE)


def test_previous_version_offline_mode_raises() -> None:
    """Offline mode + previous-value read = explicit error.

    We refuse to silently substitute the cached current value when the
    operator asked for previous; that would be a footgun.
    """
    client = make_client(make_handler())
    client.set_offline(True)

    with pytest.raises(SecrevoOfflineError):
        client.reveal_value("api-key", version="previous")


def test_invalid_version_value_raises_value_error() -> None:
    client = make_client(make_handler())

    with pytest.raises(ValueError) as info:
        client.reveal_value("api-key", version="rollback")  # type: ignore[arg-type]
    msg = str(info.value)
    assert "version" in msg
    assert "current" in msg
    assert "previous" in msg


def test_previous_version_missing_grace_header_does_not_crash() -> None:
    """If the server forgets the header (shouldn't happen, but defensive),
    the SDK accepts ``None`` rather than crashing — the value is still
    usable.
    """
    client = make_client(make_handler(grace_header=None))

    revealed = client.reveal_value("api-key", version="previous")

    assert _hash(revealed.value) == _hash(PREVIOUS_VALUE)
    assert revealed.grace_expires_at is None
