import json
import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.types import Status
from services.session_index import SessionIndex, SessionRecord


def make_record(tmp_path: Path, session_id: str = "session-1") -> SessionRecord:
    session_directory = tmp_path / session_id
    started_at = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)
    return SessionRecord(
        session_id=session_id,
        interface_name="eth0",
        started_at=started_at,
        ended_at=started_at + timedelta(minutes=2),
        pcap_path=session_directory / "capture.pcap",
        zeek_directory=session_directory / "zeek",
        zeek_log_paths=(session_directory / "zeek" / "conn.log",),
    )


def test_index_stores_session_metadata_and_file_paths(tmp_path):
    index = SessionIndex(tmp_path / "sessions")
    record = make_record(tmp_path)

    result = index.add_completed_session(record)

    assert result.status is Status.OK
    loaded = index.list_sessions()
    assert loaded.status is Status.OK
    assert loaded.value == [
        SessionRecord(
            session_id=record.session_id,
            interface_name=record.interface_name,
            started_at=record.started_at,
            ended_at=record.ended_at,
            pcap_path=record.pcap_path.resolve(),
            zeek_directory=record.zeek_directory.resolve(),
            zeek_log_paths=tuple(path.resolve() for path in record.zeek_log_paths),
        )
    ]

    payload = json.loads(index.index_path.read_text(encoding="utf-8"))
    assert payload["version"] == 1
    assert payload["sessions"][0]["interface_name"] == "eth0"
    assert payload["sessions"][0]["pcap_path"] == str(record.pcap_path.resolve())
    assert payload["sessions"][0]["zeek_log_paths"] == [
        str(record.zeek_log_paths[0].resolve())
    ]


def test_index_is_readable_from_a_fresh_instance_and_keeps_multiple_sessions(
    tmp_path,
):
    session_root = tmp_path / "sessions"
    first_instance = SessionIndex(session_root)
    records = [make_record(tmp_path, "session-1"), make_record(tmp_path, "session-2")]

    assert all(
        first_instance.add_completed_session(record).status is Status.OK
        for record in records
    )

    restored = SessionIndex(session_root).list_sessions()

    assert restored.status is Status.OK
    assert [record.session_id for record in restored.value] == [
        "session-1",
        "session-2",
    ]


def test_adding_the_same_session_twice_does_not_duplicate_it(tmp_path):
    index = SessionIndex(tmp_path / "sessions")
    record = make_record(tmp_path)

    assert index.add_completed_session(record).status is Status.OK
    assert index.add_completed_session(record).status is Status.OK

    result = index.list_sessions()
    assert result.status is Status.OK
    assert [item.session_id for item in result.value] == ["session-1"]


def test_missing_index_is_an_empty_success(tmp_path):
    result = SessionIndex(tmp_path / "missing").list_sessions()

    assert result.status is Status.OK
    assert result.value == []


@pytest.mark.parametrize(
    "contents",
    [
        "",
        "{not json",
        '{"version": 1, "sessions": "not a list"}',
        '{"version": 2, "sessions": []}',
    ],
)
def test_empty_or_malformed_index_returns_a_clear_error(tmp_path, contents):
    session_root = tmp_path / "sessions"
    session_root.mkdir()
    (session_root / "index.json").write_text(contents, encoding="utf-8")

    result = SessionIndex(session_root).list_sessions()

    assert result.status is Status.IO_ERROR
    assert result.value is None
    assert "session index" in result.detail.lower()


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits are not portable")
def test_index_and_storage_directory_are_owner_only_on_posix(tmp_path):
    index = SessionIndex(tmp_path / "sessions")

    assert index.add_completed_session(make_record(tmp_path)).status is Status.OK

    assert stat.S_IMODE(index.index_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(index.index_path.stat().st_mode) == 0o600


def test_atomic_write_failure_is_reported_without_replacing_the_index(
    tmp_path, monkeypatch
):
    index = SessionIndex(tmp_path / "sessions")
    original_replace = os.replace

    def fail_replace(source, destination):
        raise OSError("simulated storage failure")

    monkeypatch.setattr(os, "replace", fail_replace)
    result = index.add_completed_session(make_record(tmp_path))

    assert result.status is Status.IO_ERROR
    assert "simulated storage failure" in result.detail
    assert not index.index_path.exists()
    assert list(index.index_path.parent.glob(".index-*.tmp")) == []
    monkeypatch.setattr(os, "replace", original_replace)

    assert index.add_completed_session(make_record(tmp_path)).status is Status.OK


def test_index_read_permission_failure_is_reported(tmp_path, monkeypatch):
    index = SessionIndex(tmp_path / "sessions")
    assert index.add_completed_session(make_record(tmp_path)).status is Status.OK
    original_read_text = Path.read_text

    def fail_read_text(path, *args, **kwargs):
        if path == index.index_path:
            raise PermissionError("simulated read denial")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", fail_read_text)

    result = index.list_sessions()

    assert result.status is Status.PERMISSION_ERROR
    assert "simulated read denial" in result.detail
