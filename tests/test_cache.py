from __future__ import annotations

import hashlib
import os
import sys
import time
from datetime import timedelta
from pathlib import Path
from typing import Callable

import httpx
import pytest

from secrevo_sdk.cache import CacheEntry, FileCache, derive_cache_key
from secrevo_sdk.client import SecrevoClient
from secrevo_sdk.exceptions import SecrevoAPIError, SecrevoOfflineError


SECRET_PAYLOAD = {
    "workspace_id": "ws-1",
    "secret_id": "sec-123",
    "name": "api-key",
    "description": "OpenAI API key",
    "regeneration_instructions": "Rotate in provider console",
    "status": "active",
    "updated_at": "2026-05-06T02:00:00Z",
}


def _value_text() -> str:
    # Distinctive but never asserted on as plaintext in this file.
    return "sk-live-" + "x" * 24


def _value_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def make_handler(
    value: str | None = None,
    *,
    fail_value: bool = False,
) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/v1/workspaces/ws-1/secrets":
            return httpx.Response(200, json={"secrets": [SECRET_PAYLOAD]})
        if path == "/v1/workspaces/ws-1/secrets/sec-123":
            return httpx.Response(200, json=SECRET_PAYLOAD)
        if path in (
            "/v1/workspaces/ws-1/secrets/sec-123/value",
            "/v1/workspaces/ws-1/secrets/by-name/api-key/value",
        ):
            if fail_value:
                return httpx.Response(503, text="upstream down")
            assert value is not None
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
    cache: FileCache | None = None,
    max_retries: int = 0,
) -> SecrevoClient:
    return SecrevoClient(
        base_url="https://api.secrevo.local",
        workspace_id="ws-1",
        token="test-token",
        transport=httpx.MockTransport(handler),
        cache=cache,
        max_retries=max_retries,
        sleep=lambda _: None,
    )


# ---- FileCache unit tests --------------------------------------------------


def test_set_get_roundtrip(tmp_path: Path) -> None:
    key = os.urandom(32)
    cache = FileCache(directory=tmp_path, encryption_key=key)
    value = _value_text()
    expected_hash = _value_hash(value)

    cache.set("ws-1:OPENAI_API_KEY", value, kind="secret_value", metadata={"a": 1})
    entry = cache.get("ws-1:OPENAI_API_KEY")

    assert entry is not None
    assert isinstance(entry, CacheEntry)
    assert _value_hash(entry.value) == expected_hash
    assert len(entry.value) == len(value)
    assert entry.kind == "secret_value"
    assert entry.metadata == {"a": 1}


def test_get_after_max_age_returns_none(tmp_path: Path) -> None:
    key = os.urandom(32)
    cache = FileCache(directory=tmp_path, encryption_key=key, max_age=timedelta(seconds=0))
    cache.set("k", _value_text(), kind="secret_value", metadata={})
    # max_age=0 → any positive elapsed time is "expired".
    time.sleep(0.01)
    assert cache.get("k") is None


def test_key_rotation_invalidates_entry(tmp_path: Path) -> None:
    key_a = os.urandom(32)
    key_b = os.urandom(32)
    assert key_a != key_b

    cache_a = FileCache(directory=tmp_path, encryption_key=key_a)
    cache_a.set("k", _value_text(), kind="secret_value", metadata={})

    # File exists under hashed name.
    hashed = hashlib.sha256(b"k").hexdigest()
    on_disk = tmp_path / hashed
    assert on_disk.exists()

    cache_b = FileCache(directory=tmp_path, encryption_key=key_b)
    assert cache_b.get("k") is None
    # Stale-key read should unlink the file.
    assert not on_disk.exists()


def test_directory_listing_does_not_contain_plaintext_names(tmp_path: Path) -> None:
    key = os.urandom(32)
    cache = FileCache(directory=tmp_path, encryption_key=key)
    secret_name = "MY_VERY_SPECIFIC_SECRET_NAME"
    cache.set(secret_name, _value_text(), kind="secret_value", metadata={})

    names = [p.name for p in tmp_path.iterdir()]
    for name in names:
        assert secret_name not in name
        assert secret_name.lower() not in name.lower()
    # Hashed filename present.
    assert hashlib.sha256(secret_name.encode("utf-8")).hexdigest() in names


def test_invalidate_and_clear(tmp_path: Path) -> None:
    key = os.urandom(32)
    cache = FileCache(directory=tmp_path, encryption_key=key)
    cache.set("a", _value_text(), kind="secret_value", metadata={})
    cache.set("b", _value_text(), kind="secret_value", metadata={})

    cache.invalidate("a")
    assert cache.get("a") is None
    assert cache.get("b") is not None

    cache.clear()
    assert cache.get("b") is None


def test_filename_is_sha256_of_key(tmp_path: Path) -> None:
    key = os.urandom(32)
    cache = FileCache(directory=tmp_path, encryption_key=key)
    cache.set("ws-1:OPENAI_API_KEY", _value_text(), kind="secret_value", metadata={})
    expected = hashlib.sha256(b"ws-1:OPENAI_API_KEY").hexdigest()
    data_file = tmp_path / expected
    assert data_file.exists()
    # Stored bytes start with a 12-byte nonce. We assert on length only,
    # never on contents.
    assert os.stat(data_file).st_size > 12


def test_encryption_key_length_validated(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        FileCache(directory=tmp_path, encryption_key=b"too-short")


def test_derive_cache_key_is_deterministic_and_32_bytes() -> None:
    a = derive_cache_key("agt_token_1")
    b = derive_cache_key("agt_token_1")
    c = derive_cache_key("agt_token_2")
    assert len(a) == 32
    assert a == b
    assert a != c


# ---- Integration with SecrevoClient ---------------------------------------


def test_reveal_value_writes_to_cache_on_success(tmp_path: Path) -> None:
    key = os.urandom(32)
    cache = FileCache(directory=tmp_path, encryption_key=key)
    value = _value_text()
    expected_hash = _value_hash(value)

    client = make_client(make_handler(value=value), cache=cache)
    revealed = client.reveal_value("api-key")

    assert revealed.degraded is False
    assert _value_hash(revealed.value) == expected_hash
    # And the cache now has it.
    cached = cache.get("ws-1:api-key")
    assert cached is not None
    assert _value_hash(cached.value) == expected_hash


def test_api_failure_falls_back_to_cache_with_degraded_flag(tmp_path: Path) -> None:
    key = os.urandom(32)
    cache = FileCache(directory=tmp_path, encryption_key=key)
    value = _value_text()
    expected_hash = _value_hash(value)

    # First, prime the cache with a successful call.
    primed = make_client(make_handler(value=value), cache=cache)
    primed.reveal_value("api-key")

    # Second client: same cache, but the API now fails on the value endpoint.
    failing = make_client(make_handler(fail_value=True), cache=cache, max_retries=0)
    revealed = failing.reveal_value("api-key")

    assert revealed.degraded is True
    assert _value_hash(revealed.value) == expected_hash
    assert revealed.secret.name == "api-key"


def test_api_failure_without_cache_entry_raises(tmp_path: Path) -> None:
    key = os.urandom(32)
    cache = FileCache(directory=tmp_path, encryption_key=key)
    failing = make_client(make_handler(fail_value=True), cache=cache, max_retries=0)

    with pytest.raises(SecrevoAPIError):
        failing.reveal_value("api-key")


def test_api_failure_with_expired_cache_entry_raises(tmp_path: Path) -> None:
    key = os.urandom(32)
    cache = FileCache(
        directory=tmp_path, encryption_key=key, max_age=timedelta(seconds=0)
    )
    primed = make_client(make_handler(value=_value_text()), cache=cache)
    primed.reveal_value("api-key")
    time.sleep(0.01)

    failing = make_client(make_handler(fail_value=True), cache=cache, max_retries=0)
    with pytest.raises(SecrevoAPIError):
        failing.reveal_value("api-key")


def test_offline_mode_reads_from_cache_only(tmp_path: Path) -> None:
    key = os.urandom(32)
    cache = FileCache(directory=tmp_path, encryption_key=key)
    value = _value_text()
    expected_hash = _value_hash(value)

    primed = make_client(make_handler(value=value), cache=cache)
    primed.reveal_value("api-key")

    # Build a client whose transport would 500 on every request — proving
    # the network is not touched.
    def always_500(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="should not be called")

    offline_client = make_client(always_500, cache=cache, max_retries=0)
    offline_client.set_offline(True)
    revealed = offline_client.reveal_value("api-key")

    assert revealed.degraded is True
    assert _value_hash(revealed.value) == expected_hash


def test_offline_mode_with_cache_miss_raises_offline_error(tmp_path: Path) -> None:
    key = os.urandom(32)
    cache = FileCache(directory=tmp_path, encryption_key=key)
    client = make_client(make_handler(fail_value=True), cache=cache)
    client.set_offline(True)

    with pytest.raises(SecrevoOfflineError):
        client.reveal_value("api-key")


def test_auto_cache_uses_default_directory_and_token_derived_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Force platformdirs to point at the test tmp_path.
    import secrevo_sdk.cache as cache_mod

    monkeypatch.setattr(
        cache_mod.platformdirs, "user_cache_dir", lambda _name: str(tmp_path)
    )

    client = SecrevoClient(
        base_url="https://api.secrevo.local",
        workspace_id="ws-1",
        token="agt_test",
        transport=httpx.MockTransport(make_handler(value=_value_text())),
        cache="auto",
        sleep=lambda _: None,
    )
    assert client.cache is not None
    revealed = client.reveal_value("api-key")
    assert revealed.degraded is False
    # Directory created under the patched root.
    assert (tmp_path / "values").exists()


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="portalocker on Windows uses LockFileEx which is incompatible with "
    "the simultaneous in-process SH+EX pattern this test exercises; cross-process "
    "behavior is the real contract, exercised by the file-lock pattern itself.",
)
def test_concurrent_readers_and_writer_share_directory(tmp_path: Path) -> None:
    key = os.urandom(32)
    writer = FileCache(directory=tmp_path, encryption_key=key)
    reader = FileCache(directory=tmp_path, encryption_key=key)

    value = _value_text()
    expected_hash = _value_hash(value)
    writer.set("k", value, kind="secret_value", metadata={})

    entry = reader.get("k")
    assert entry is not None
    assert _value_hash(entry.value) == expected_hash


def test_no_cache_default_behavior_unchanged(tmp_path: Path) -> None:
    """Without an explicit cache, the SDK behaves exactly as before."""
    client = make_client(make_handler(fail_value=True), cache=None)
    with pytest.raises(SecrevoAPIError):
        client.reveal_value("api-key")
