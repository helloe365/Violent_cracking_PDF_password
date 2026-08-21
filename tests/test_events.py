from __future__ import annotations

import json
from datetime import datetime, timedelta
from io import StringIO

import pytest

from pdf_password_recovery import EventType, JsonLineSink, RecoveryEvent, event_payload
from pdf_password_recovery.errors import CapabilityError, ConfigurationError, PlanSchemaError


def test_json_line_sink_writes_the_schema_one_event_contract() -> None:
    stream = StringIO()
    event = RecoveryEvent(
        type=EventType.PROGRESS,
        timestamp="2026-08-22T12:34:56Z",
        session="demo-1",
        payload={"completed": 12, "total": 40},
    )

    JsonLineSink(stream).emit(event)

    line = stream.getvalue()
    assert line == (
        '{"schema":1,"type":"progress","timestamp":"2026-08-22T12:34:56Z",'
        '"session":"demo-1","payload":{"completed":12,"total":40}}\n'
    )
    assert json.loads(line) == {
        "schema": 1,
        "type": "progress",
        "timestamp": "2026-08-22T12:34:56Z",
        "session": "demo-1",
        "payload": {"completed": 12, "total": 40},
    }


def test_event_defaults_to_a_utc_schema_one_timestamp() -> None:
    event = RecoveryEvent(type=EventType.PREFLIGHT, payload={})

    assert event.schema == 1
    assert event.timestamp.endswith("Z")
    assert datetime.fromisoformat(
        event.timestamp.removesuffix("Z") + "+00:00"
    ).utcoffset() == timedelta(0)


def test_json_line_sink_preserves_unicode_characters() -> None:
    stream = StringIO()

    JsonLineSink(stream).emit(
        RecoveryEvent(
            type=EventType.WARNING,
            timestamp="2026-08-22T12:34:56Z",
            session=None,
            payload={"message": "密码提示：北京"},
        )
    )

    assert '"message":"密码提示：北京"' in stream.getvalue()
    assert "\\u" not in stream.getvalue()


@pytest.mark.parametrize(
    "payload",
    [
        {"password": "secret"},
        {"stage": {"pdf_hash": "$pdf$example"}},
        {"items": [{"extracted_hash": "$pdf$example"}]},
    ],
)
def test_event_rejects_sensitive_keys_at_any_nested_mapping_depth(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ConfigurationError) as raised:
        RecoveryEvent(type=EventType.ERROR, payload=payload)

    assert raised.value.code == "configuration"


def test_event_payload_rechecks_mutated_nested_payloads() -> None:
    payload: dict[str, object] = {"stage": {"id": "dictionary"}}
    event = RecoveryEvent(type=EventType.CHECKPOINT, payload=payload)
    nested = payload["stage"]
    assert isinstance(nested, dict)
    nested["password"] = "secret"

    with pytest.raises(ConfigurationError) as raised:
        event_payload(event)

    assert raised.value.code == "configuration"


def test_event_schema_is_fixed_at_one() -> None:
    with pytest.raises(ConfigurationError):
        RecoveryEvent(type=EventType.RESULT, payload={}, schema=2)


def test_event_type_values_are_stable() -> None:
    assert {event_type.value for event_type in EventType} == {
        "preflight",
        "stage_started",
        "progress",
        "warning",
        "checkpoint",
        "result",
        "error",
    }


def test_upgrade_error_codes_are_stable_without_changing_exception_messages() -> None:
    assert str(PlanSchemaError("invalid plan")) == "invalid plan"
    assert PlanSchemaError("invalid plan").code == "plan_schema"
    assert CapabilityError("missing option").code == "capability"
