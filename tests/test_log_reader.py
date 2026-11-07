from pathlib import Path

from core.types import Status
from services.capture_service import CaptureSession
from services.log_reader import LogReader

CONN_HEADER = """#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tconn
#open\t2026-01-01-00-00-00
#fields\tts\tuid\tid.orig_h\tid.resp_h\tservice
#types\ttime\tstring\taddr\taddr\tstring
"""
NOTICE_HEADER = """#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tnotice
#fields\tts\tuid\tnote\tmsg
#types\ttime\tstring\tenum\tstring
"""


def make_session(tmp_path: Path, session_id: str = "session-1") -> CaptureSession:
    directory = tmp_path / session_id
    zeek_directory = directory / "zeek"
    zeek_directory.mkdir(parents=True)
    return CaptureSession(
        session_id=session_id,
        interface_name="eth0",
        session_directory=directory,
        pcap_path=directory / "capture.pcap",
        zeek_directory=zeek_directory,
    )


def test_reads_standard_zeek_headers_and_new_entries_incrementally(tmp_path):
    session = make_session(tmp_path)
    log = session.zeek_directory / "conn.log"
    log.write_text(CONN_HEADER + "1.0\tC1\t10.0.0.1\t8.8.8.8\tdns\n")
    reader = LogReader()

    initial = reader.read(session, ["conn"])
    repeated = reader.read(session, ["conn.log"])
    with log.open("a") as file:
        file.write("2.0\tC2\t10.0.0.2\t-\t(empty)\n")
    appended = reader.read(session, ["conn"])

    assert initial.status is Status.OK
    assert [r.fields["uid"] for r in initial.value] == ["C1"]
    assert initial.value[0].fields["id.orig_h"] == "10.0.0.1"
    assert repeated.status is Status.OK and repeated.value == []
    assert appended.value[0].fields == {
        "ts": "2.0", "uid": "C2", "id.orig_h": "10.0.0.2",
        "id.resp_h": None, "service": "",
    }


def test_keeps_partial_line_until_it_is_completed(tmp_path):
    session = make_session(tmp_path)
    log = session.zeek_directory / "conn.log"
    log.write_text(CONN_HEADER + "1.0\tC1\t10.0")
    reader = LogReader()

    assert reader.read(session, ["conn"]).value == []
    with log.open("a") as file:
        file.write(".0.1\t8.8.8.8\tdns\n")
    result = reader.read(session, ["conn"])

    assert result.status is Status.OK
    assert [record.fields["uid"] for record in result.value] == ["C1"]


def test_reads_multiple_logs_and_sessions_with_independent_cursors(tmp_path):
    first = make_session(tmp_path, "first")
    second = make_session(tmp_path, "second")
    (first.zeek_directory / "conn.log").write_text(CONN_HEADER + "1\tA\ta\tb\t-\n")
    (first.zeek_directory / "notice.log").write_text(NOTICE_HEADER + "1\tA\tScan\tmessage\n")
    (second.zeek_directory / "conn.log").write_text(CONN_HEADER + "2\tB\tc\td\thttp\n")
    reader = LogReader()

    first_result = reader.read(first)
    second_result = reader.read(second, ["conn"])

    assert [(r.session_id, r.log_name) for r in first_result.value] == [
        ("first", "conn"), ("first", "notice")
    ]
    assert second_result.value[0].fields["uid"] == "B"
    assert reader.read(first).value == []


def test_missing_empty_and_malformed_logs_are_graceful(tmp_path):
    session = make_session(tmp_path)
    reader = LogReader()
    missing = reader.read(session, ["notice"])
    (session.zeek_directory / "conn.log").write_text(CONN_HEADER + "bad\tline\n")
    malformed = reader.read(session, ["conn"])
    (session.zeek_directory / "notice.log").touch()
    empty = reader.read(session, ["notice"])

    assert missing.status is Status.OK and missing.value == []
    assert malformed.status is Status.OK and malformed.value == []
    assert "Skipped 1" in malformed.detail
    assert empty.status is Status.OK and empty.value == []


def test_handles_truncation_and_rotation_as_a_new_log(tmp_path):
    session = make_session(tmp_path)
    log = session.zeek_directory / "conn.log"
    log.write_text(CONN_HEADER + "1\tOLD\ta\tb\tssl\n")
    reader = LogReader()
    assert reader.read(session, ["conn"]).value[0].fields["uid"] == "OLD"

    log.write_text(CONN_HEADER + "2\tNEW\tc\td\thttp\n")
    truncated = reader.read(session, ["conn"])
    assert [record.fields["uid"] for record in truncated.value] == ["NEW"]

    rotated = session.zeek_directory / "conn.log.1"
    log.rename(rotated)
    log.write_text(CONN_HEADER + "3\tROTATED\te\tf\tdns\n")
    rotation = reader.read(session, ["conn"])
    assert [record.fields["uid"] for record in rotation.value] == ["ROTATED"]


def test_consumers_with_separate_readers_do_not_interfere(tmp_path):
    session = make_session(tmp_path)
    (session.zeek_directory / "notice.log").write_text(
        NOTICE_HEADER + "1\tA\tScan\tmessage\n"
    )

    dashboard_reader = LogReader()
    alert_reader = LogReader()

    assert dashboard_reader.read(session, ["notice"]).value[0].fields["note"] == "Scan"
    assert alert_reader.read(session, ["notice"]).value[0].fields["note"] == "Scan"
