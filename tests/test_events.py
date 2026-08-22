from __future__ import annotations

import json
from datetime import datetime, timedelta
from enum import StrEnum
from io import StringIO

import pytest

from pdf_password_recovery import (
    EventMessage,
    EventType,
    JsonLineSink,
    RecoveryEvent,
    event_payload,
)
from pdf_password_recovery.errors import CapabilityError, ConfigurationError, PlanSchemaError


class _UnsafeStatus(StrEnum):
    PDF_HASH = "$pdf$5*5*example"
    HINT = "密码提示：北京"


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
    event = RecoveryEvent(type=EventType.PREFLIGHT, payload={"status": "ready"})

    assert event.schema == 1
    assert event.timestamp.endswith("Z")
    assert datetime.fromisoformat(
        event.timestamp.removesuffix("Z") + "+00:00"
    ).utcoffset() == timedelta(0)


def test_json_line_sink_preserves_controlled_unicode_message_characters() -> None:
    stream = StringIO()

    JsonLineSink(stream).emit(
        RecoveryEvent(
            type=EventType.WARNING,
            timestamp="2026-08-22T12:34:56Z",
            session=None,
            payload={"message": EventMessage.READY},
        )
    )

    assert '"message":"已就绪"' in stream.getvalue()
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
    payload: dict[str, object] = {"device_ids": []}
    event = RecoveryEvent(type=EventType.PREFLIGHT, payload=payload)
    nested = payload["device_ids"]
    assert isinstance(nested, list)
    nested.append({"password": EventMessage.CONFIGURATION_INVALID})

    with pytest.raises(ConfigurationError) as raised:
        event_payload(event)

    assert raised.value.code == "configuration"


def test_event_rejection_does_not_echo_an_unknown_sensitive_field() -> None:
    sensitive_key = "$pdf$5*5*example"

    with pytest.raises(ConfigurationError) as raised:
        RecoveryEvent(type=EventType.PREFLIGHT, payload={sensitive_key: 1})

    assert sensitive_key not in str(raised.value)


@pytest.mark.parametrize(
    "payload",
    [
        {"message": "Password hint: autumn"},
        {"message": "密码提示：北京"},
        {"context": [{"text": "private prompt"}]},
    ],
)
def test_event_rejects_free_text_at_any_nested_depth(payload: dict[str, object]) -> None:
    with pytest.raises(ConfigurationError):
        RecoveryEvent(type=EventType.WARNING, payload=payload)


def test_event_allows_hint_counts_and_fixed_enum_statuses() -> None:
    event = RecoveryEvent(
        type=EventType.PREFLIGHT,
        payload={
            "hint_count": 2,
            "status": "ready",
            "device_ids": ["1"],
        },
    )

    assert event_payload(event)["payload"] == {
        "hint_count": 2,
        "status": "ready",
        "device_ids": ["1"],
    }


@pytest.mark.parametrize(
    "key,value",
    [
        ("token", "$pdf$5*5*example"),
        ("hints_content", "a private clue"),
    ],
)
def test_json_line_sink_rejects_sensitive_data_mutated_after_event_construction(
    key: str,
    value: str,
) -> None:
    payload: dict[str, object] = {"device_ids": []}
    event = RecoveryEvent(type=EventType.PREFLIGHT, payload=payload)
    nested = payload["device_ids"]
    assert isinstance(nested, list)
    nested.append({key: value})
    stream = StringIO()

    with pytest.raises(ConfigurationError):
        JsonLineSink(stream).emit(event)

    assert stream.getvalue() == ""


@pytest.mark.parametrize(
    "event_type,payload",
    [
        (
            EventType.PREFLIGHT,
            {
                "status": "ready",
                "backend": "hashcat",
                "device_ids": ["1"],
                "tool_version": "7.1.2",
                "workload": "balanced",
                "pdf_mode": 10500,
            },
        ),
        (
            EventType.STAGE_STARTED,
            {
                "stage_id": "dictionary",
                "stage_index": 0,
                "stage_count": 3,
                "backend": "cpu",
                "workload": "quiet",
                "total": 100,
            },
        ),
        (
            EventType.PROGRESS,
            {
                "stage_id": "dictionary",
                "completed": 10,
                "total": 100,
                "attempted": 10,
                "elapsed_seconds": 1.5,
                "rate": 7.0,
                "backend": "cpu",
                "workers": 2,
            },
        ),
        (
            EventType.WARNING,
            {
                "code": "capability",
                "message": EventMessage.HASHCAT_UNAVAILABLE,
                "backend": "hashcat",
            },
        ),
        (
            EventType.CHECKPOINT,
            {
                "stage_id": "dictionary",
                "completed": 10,
                "total": 100,
                "checkpoint_status": "saved",
            },
        ),
        (
            EventType.RESULT,
            {
                "status": "found",
                "stage_id": "dictionary",
                "attempted": 10,
                "elapsed_seconds": 1.5,
                "backend": "cpu",
                "output_path": "artifacts/result.json",
            },
        ),
        (
            EventType.ERROR,
            {
                "code": "configuration",
                "message": EventMessage.CONFIGURATION_INVALID,
                "stage_id": "dictionary",
                "backend": "cpu",
            },
        ),
    ],
)
def test_every_event_type_accepts_its_safe_payload(
    event_type: EventType,
    payload: dict[str, object],
) -> None:
    assert event_payload(RecoveryEvent(type=event_type, payload=payload))["payload"] == payload


@pytest.mark.parametrize("session", ["../escape", "nested/name", "密码", "$pdf$5*5*example"])
def test_event_rejects_unsafe_session_identifiers(session: str) -> None:
    with pytest.raises(ConfigurationError):
        RecoveryEvent(type=EventType.PROGRESS, session=session, payload={"completed": 1})


@pytest.mark.parametrize(
    "event_type,payload",
    [
        (EventType.WARNING, {"message": _UnsafeStatus.PDF_HASH}),
        (EventType.WARNING, {"message": _UnsafeStatus.HINT}),
        (EventType.PREFLIGHT, {"device_ids": [{"message": EventMessage.READY}]}),
    ],
)
def test_event_rejects_unsafe_enum_and_nested_structure_bypasses(
    event_type: EventType,
    payload: dict[str, object],
) -> None:
    with pytest.raises(ConfigurationError):
        RecoveryEvent(type=event_type, payload=payload)


def test_json_line_sink_rejects_nonfinite_json_values() -> None:
    payload: dict[str, object] = {"rate": 1.0}
    event = RecoveryEvent(type=EventType.PROGRESS, payload=payload)
    payload["rate"] = float("nan")
    stream = StringIO()

    with pytest.raises(ConfigurationError):
        JsonLineSink(stream).emit(event)

    assert stream.getvalue() == ""


def test_event_schema_is_fixed_at_one() -> None:
    for schema in (2, 1.0, True):
        with pytest.raises(ConfigurationError):
            RecoveryEvent(type=EventType.RESULT, payload={}, schema=schema)  # type: ignore[arg-type]

    assert RecoveryEvent(type=EventType.RESULT, payload={}, schema=1).schema == 1


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
