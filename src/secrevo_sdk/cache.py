"""Encrypted on-disk cache for revealed Secrevo secrets.

The cache is opt-in (``pip install secrevo-sdk[cache]``) and exists for
long-running services on intermittent networks: when the API is
unreachable, the SDK can hand back the last known good value flagged
as ``degraded=True`` instead of crashing the worker.

Threat model
------------

* Entries are encrypted at rest with AES-256-GCM. The key is derived
  from the agent token via HKDF-SHA256, so a token rotation invalidates
  the entire cache automatically (decrypt fails → entry is unlinked).
* Filenames on disk are ``sha256(secret_name)``; the directory listing
  never leaks plaintext secret names.
* The cache never logs values. It logs structured events
  (``cache_hit``, ``cache_miss``, ``cache_write``, ``fallback_to_cache``)
  keyed by secret name only.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    import platformdirs
    import portalocker
except ImportError as exc:  # pragma: no cover - exercised by import guard
    raise ImportError(
        "secrevo_sdk.cache requires the optional cache extras. "
        "Install with: pip install 'secrevo-sdk[cache]'"
    ) from exc


logger = logging.getLogger("secrevo_sdk.cache")

_HKDF_INFO = b"secrevo-sdk-cache-v1"
_NONCE_LEN = 12
_KEY_LEN = 32


@dataclass(frozen=True, slots=True)
class CacheEntry:
    """A successfully decrypted cache record.

    ``fetched_at`` is the UTC timestamp at which the value was last
    written. Staleness (``max_age``) is enforced by :class:`FileCache`,
    not by the consumer.
    """

    value: str
    kind: str
    metadata: dict[str, Any] = field(default_factory=dict)
    fetched_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def derive_cache_key(token: str | bytes) -> bytes:
    """Derive a 32-byte AES key from the SDK's agent token.

    Exposed for callers that want to pass an explicit ``encryption_key``
    to :class:`FileCache` without re-deriving the HKDF themselves.
    """
    token_bytes = token.encode("utf-8") if isinstance(token, str) else bytes(token)
    if not token_bytes:
        raise ValueError("token must be non-empty to derive a cache key")
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_LEN,
        salt=None,
        info=_HKDF_INFO,
    )
    return kdf.derive(token_bytes)


def _default_directory() -> Path:
    return Path(platformdirs.user_cache_dir("secrevo")) / "values"


def _filename_for(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


class FileCache:
    """Encrypted, file-backed cache for revealed secret values.

    Per-entry layout on disk: ``nonce (12 bytes) || AESGCM(ciphertext+tag)``.
    Plaintext payload is JSON ``{value, kind, metadata, fetched_at}``.

    The cache is concurrency-safe across processes: writes take an
    exclusive ``portalocker`` lock, reads take a shared lock. Lock
    files share the same name as the data file with a ``.lock`` suffix
    so OS-level file replacement on Windows doesn't invalidate the
    lock handle held by another process.
    """

    def __init__(
        self,
        directory: str | Path | None = None,
        encryption_key: bytes | None = None,
        max_age: timedelta = timedelta(hours=24),
    ) -> None:
        if encryption_key is None:
            raise ValueError(
                "encryption_key is required. Pass derive_cache_key(token) or let "
                "SecrevoClient(cache='auto') derive it for you."
            )
        if len(encryption_key) != _KEY_LEN:
            raise ValueError(
                f"encryption_key must be {_KEY_LEN} bytes (got {len(encryption_key)})"
            )
        self._directory = Path(directory) if directory is not None else _default_directory()
        self._directory.mkdir(parents=True, exist_ok=True)
        self._aead = AESGCM(encryption_key)
        self._max_age = max_age

    @property
    def directory(self) -> Path:
        return self._directory

    @property
    def max_age(self) -> timedelta:
        return self._max_age

    def get(self, key: str) -> CacheEntry | None:
        path = self._path_for(key)
        lock_path = self._lock_path_for(key)
        if not path.exists():
            logger.debug("cache_miss key=%s reason=no_file", key)
            return None
        try:
            with portalocker.Lock(
                str(lock_path), mode="a+", timeout=5, flags=portalocker.LOCK_SH
            ):
                raw = path.read_bytes()
        except (portalocker.LockException, FileNotFoundError):
            logger.debug("cache_miss key=%s reason=lock_or_gone", key)
            return None

        if len(raw) <= _NONCE_LEN:
            logger.debug("cache_miss key=%s reason=truncated", key)
            self._unlink_quiet(path)
            return None
        nonce, blob = raw[:_NONCE_LEN], raw[_NONCE_LEN:]
        try:
            plaintext = self._aead.decrypt(nonce, blob, None)
        except Exception:
            # Wrong key (token rotated) or tampering. Drop the file so
            # subsequent reads don't keep paying the decrypt cost, and
            # so the operator can re-populate after rotation.
            logger.debug("decrypt_failed_stale_key key=%s", key)
            self._unlink_quiet(path)
            return None

        try:
            payload = json.loads(plaintext.decode("utf-8"))
            entry = CacheEntry(
                value=payload["value"],
                kind=payload.get("kind", ""),
                metadata=payload.get("metadata", {}) or {},
                fetched_at=datetime.fromisoformat(payload["fetched_at"]),
            )
        except (KeyError, ValueError, json.JSONDecodeError):
            logger.debug("cache_miss key=%s reason=malformed_payload", key)
            self._unlink_quiet(path)
            return None

        if self._is_expired(entry):
            logger.debug("cache_miss key=%s reason=expired", key)
            return None
        logger.debug("cache_hit key=%s", key)
        return entry

    def set(self, key: str, value: str, kind: str, metadata: dict[str, Any]) -> None:
        payload = {
            "value": value,
            "kind": kind,
            "metadata": metadata or {},
            "fetched_at": datetime.now(timezone.utc).isoformat(),
        }
        plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        nonce = secrets.token_bytes(_NONCE_LEN)
        ciphertext = self._aead.encrypt(nonce, plaintext, None)
        blob = nonce + ciphertext

        path = self._path_for(key)
        lock_path = self._lock_path_for(key)
        # Write to a sibling temp file then atomic-replace, under EX lock.
        tmp_path = path.with_suffix(".tmp")
        with portalocker.Lock(
            str(lock_path), mode="a+", timeout=10, flags=portalocker.LOCK_EX
        ):
            tmp_path.write_bytes(blob)
            try:
                os.replace(tmp_path, path)
            except OSError:
                # Best effort cleanup if replace fails for any reason.
                self._unlink_quiet(tmp_path)
                raise
        logger.debug("cache_write key=%s bytes=%d", key, len(blob))

    def invalidate(self, key: str) -> None:
        self._unlink_quiet(self._path_for(key))
        # The lock file is fine to leave behind; it's empty and reusable.

    def clear(self) -> None:
        if not self._directory.exists():
            return
        for child in self._directory.iterdir():
            if child.is_file():
                self._unlink_quiet(child)

    # --- internals ------------------------------------------------------

    def _path_for(self, key: str) -> Path:
        return self._directory / _filename_for(key)

    def _lock_path_for(self, key: str) -> Path:
        return self._directory / (_filename_for(key) + ".lock")

    def _is_expired(self, entry: CacheEntry) -> bool:
        age = datetime.now(timezone.utc) - entry.fetched_at
        return age > self._max_age

    @staticmethod
    def _unlink_quiet(path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            return
        except OSError:
            # On Windows another handle may keep the file open briefly.
            # Treat this as best-effort; the next write will overwrite.
            logger.debug("unlink_failed path=%s", path)
