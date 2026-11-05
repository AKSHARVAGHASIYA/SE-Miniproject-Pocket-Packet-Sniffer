from pathlib import Path

from core.types import Status
from services.capture_service import CaptureSession
from services.log_reader import LogReader
from services.summary_service import SummaryService, render_summary


CONN_HEADER = """#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tconn
#fields\tts\tuid\tproto\tid.orig_h\tid.resp_h
#types\ttime\tstring\tenum\taddr\taddr
"""


def make_session(tmp_path: Path, session_id: str) -> CaptureSession:
    directory = tmp_path / session_id
    zeek = directory / "zeek"
    zeek.mkdir(parents=True)
    return CaptureSession(session_id, "eth0", directory, directory / "capture.pcap", zeek)


def append(log: Path, *rows: str) -> None:
    with log.open("a", encoding="utf-8") as handle:
        handle.write("".join(f"{row}\n" for row in rows))


def test_aggregates_protocols_connections_and_endpoint_talkers_incrementally(tmp_path):
    session = make_session(tmp_path, "one")
    log = session.zeek_directory / "conn.log"
    log.write_text(CONN_HEADER + "1\ta\ttcp\t10.0.0.1\t10.0.0.2\n", encoding="utf-8")
    service = SummaryService()

    first = service.get_summary(session)
    repeated = service.get_summary(session)
    append(log, "2\tb\tudp\t10.0.0.1\t8.8.8.8")
    updated = service.get_summary(session)

    assert first.status is Status.OK
    assert first.value.connection_count == 1
    assert first.value.protocol_breakdown == {"tcp": 1}
    assert first.value.top_talkers == [("10.0.0.1", 1), ("10.0.0.2", 1)]
    assert repeated.value.connection_count == 1
    assert updated.value.protocol_breakdown == {"tcp": 1, "udp": 1}
    assert updated.value.top_talkers == [("10.0.0.1", 2), ("10.0.0.2", 1), ("8.8.8.8", 1)]


def test_unknown_protocol_missing_hosts_self_connection_and_ties(tmp_path):
    session = make_session(tmp_path, "one")
    (session.zeek_directory / "conn.log").write_text(
        CONN_HEADER
        + "1\ta\t-\t10.0.0.2\t10.0.0.2\n"
        + "2\tb\t(empty)\t-\t-\n"
        + "3\tc\tTCP\t10.0.0.1\t10.0.0.2\n",
        encoding="utf-8",
    )

    summary = SummaryService().get_summary(session).value

    assert summary.protocol_breakdown == {"tcp": 1, "unknown": 2}
    assert summary.connection_count == 3
    # A self-connection counts once; missing addresses are not hosts.
    assert summary.top_talkers == [("10.0.0.2", 2), ("10.0.0.1", 1)]


def test_session_totals_are_independent(tmp_path):
    first = make_session(tmp_path, "first")
    second = make_session(tmp_path, "second")
    (first.zeek_directory / "conn.log").write_text(CONN_HEADER + "1\ta\ttcp\ta\tb\n", encoding="utf-8")
    (second.zeek_directory / "conn.log").write_text(CONN_HEADER + "1\tb\tudp\tc\td\n", encoding="utf-8")
    service = SummaryService()

    first_summary = service.get_summary(first).value
    second_summary = service.get_summary(second).value

    assert first_summary.connection_count == 1
    assert first_summary.protocol_breakdown == {"tcp": 1}
    assert second_summary.connection_count == 1
    assert second_summary.protocol_breakdown == {"udp": 1}


def test_empty_summary_and_reader_errors_are_clear(tmp_path):
    session = make_session(tmp_path, "empty")
    service = SummaryService()
    empty = service.get_summary(session)

    assert empty.status is Status.OK
    assert empty.value.connection_count == 0
    assert empty.value.protocol_breakdown == {}
    assert empty.value.top_talkers == []

    log = session.zeek_directory / "conn.log"
    log.mkdir()
    error = service.get_summary(session)
    assert error.status in {Status.PERMISSION_ERROR, Status.IO_ERROR}


def test_render_summary_explains_top_talker_measure_and_empty_state(tmp_path):
    session = make_session(tmp_path, "one")
    (session.zeek_directory / "conn.log").write_text(CONN_HEADER + "1\ta\ttcp\ta\tb\n", encoding="utf-8")
    summary = SummaryService().get_summary(session).value

    rendered = render_summary(summary)
    assert "Total connections: 1" in rendered
    assert "a: 1 connection(s)" in rendered
    assert "top talker" in rendered
    assert "not packet or byte volume" in rendered

    empty = render_summary(type(summary)({}, [], 0, summary.updated_at))
    assert "No complete conn.log records" in empty
    assert "start traffic" in empty

