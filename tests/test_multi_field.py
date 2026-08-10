"""Multi-field secrets: one credential made of several named parts."""

from __future__ import annotations

import pytest

from secrevo_sdk.models import SecretRecord, SecretValue

SCALAR_PAYLOAD = {
    "workspace_id": "workspace-0001",
    "secret_id": "secret-0001",
    "name": "OPENAI_API_KEY",
    "status": "active",
    "updated_at": "2026-08-10T00:00:00Z",
}


def _record(**extra) -> SecretRecord:
    return SecretRecord.from_payload({**SCALAR_PAYLOAD, **extra})


def test_scalar_secret_has_no_fields() -> None:
    """Absent means scalar — the shape of every secret that predates this."""
    assert _record().fields == []


def test_field_names_are_parsed() -> None:
    record = _record(fields=["clave", "ruc", "usuario"])
    assert record.fields == ["clave", "ruc", "usuario"]


def test_scalar_value_is_unchanged() -> None:
    value = SecretValue.from_payload(_record(), {"value": "sk-abc"})
    assert value.value == "sk-abc"
    assert value.fields == {}


def test_multi_field_payload_carries_no_value_key() -> None:
    """A bundle has no single value, so requiring one would raise a misleading
    "missing value" error for a perfectly well-formed payload."""
    value = SecretValue.from_payload(
        _record(fields=["clave", "usuario"]),
        {"fields": {"usuario": "u", "clave": "c"}},
    )
    assert value.value == ""
    assert value.fields == {"usuario": "u", "clave": "c"}


def test_field_value_selects_one() -> None:
    value = SecretValue.from_payload(
        _record(), {"fields": {"usuario": "u", "clave": "c"}}
    )
    assert value.field_value("clave") == "c"


def test_missing_field_names_the_available_ones_never_values() -> None:
    value = SecretValue.from_payload(
        _record(), {"fields": {"usuario": "u", "clave": "c"}}
    )
    with pytest.raises(KeyError) as excinfo:
        value.field_value("clve")
    message = str(excinfo.value)
    assert "clve" in message
    assert "clave" in message and "usuario" in message
    # A typo must never be diagnosed by printing credential material.
    assert "'u'" not in message and '"u"' not in message


def test_field_value_on_scalar_points_at_value() -> None:
    value = SecretValue.from_payload(_record(), {"value": "sk-abc"})
    with pytest.raises(KeyError) as excinfo:
        value.field_value("clave")
    assert "single value" in str(excinfo.value)
