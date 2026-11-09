from pathlib import Path
import shutil

from core.types import Status
from services.alert_service import AlertService
from services.capture_service import CaptureSession

NOTICE_HEADER = """#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tnotice
#fields\tts\tuid\tnote\tmsg\tsrc\tdst\tp
#types\ttime\tstring\tenum\tstring\taddr\taddr\tport
"""


def make_session(tmp_path: Path, session_id: str) -> CaptureSession:
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


def append_notices(log: Path, *rows: str) -> None:
    with log.open("a", encoding="utf-8") as handle:
        handle.write("".join(f"{row}\n" for row in rows))


def test_alerting_is_disabled_by_default(tmp_path):
    session = make_session(tmp_path, "one")
    service = AlertService()

    assert service.is_enabled(session) is False


def test_enable_and_disable_alerting_for_session(tmp_path):
    session = make_session(tmp_path, "one")
    service = AlertService()

    enabled = service.set_enabled(session, True)
    disabled = service.set_enabled(session, False)

    assert enabled.status is Status.OK
    assert enabled.value is True
    assert disabled.status is Status.OK
    assert disabled.value is False
    assert service.is_enabled(session) is False


def test_collects_supported_scan_notices(tmp_path):
    session = make_session(tmp_path, "one")
    log = session.zeek_directory / "notice.log"
    log.write_text(NOTICE_HEADER, encoding="utf-8")

    append_notices(
        log,
        "1.0\tA\tScan::Address_Scan\tAddress scan detected\t10.0.0.1\t-\t445",
        "2.0\tB\tScan::Port_Scan\tPort scan detected\t10.0.0.2\t10.0.0.3\t22",
        "3.0\tC\tScan::Random_Scan\tRandom scan detected\t10.0.0.4\t-\t-",
    )

    service = AlertService()
    service.set_enabled(session, True)

    result = service.get_alerts(session)

    assert result.status is Status.OK
    assert len(result.value) == 3
    assert [alert.note for alert in result.value] == [
        "Scan::Port_Scan",
        "Scan::Address_Scan",
        "Scan::Random_Scan",
    ]

    assert [alert.priority for alert in result.value] == [
        "HIGH",
        "MEDIUM",
        "LOW",
    ]
    assert result.value[0].source == "10.0.0.2"
    assert result.value[0].port == "22"
    assert result.value[1].source == "10.0.0.1"
    assert result.value[1].port == "445"
    assert result.value[0].destination == "10.0.0.3"


def test_ignores_unsupported_notice_types(tmp_path):
    session = make_session(tmp_path, "one")
    log = session.zeek_directory / "notice.log"
    log.write_text(NOTICE_HEADER, encoding="utf-8")

    append_notices(
        log,
        "1.0\tA\tSome_Other_Notice\tOther event\t10.0.0.1\t-\t-",
    )

    service = AlertService()
    service.set_enabled(session, True)

    result = service.get_alerts(session)

    assert result.status is Status.OK
    assert result.value == []


def test_reads_new_notices_incrementally_without_duplicates(tmp_path):
    session = make_session(tmp_path, "one")
    log = session.zeek_directory / "notice.log"
    log.write_text(NOTICE_HEADER, encoding="utf-8")

    service = AlertService()
    service.set_enabled(session, True)

    append_notices(
        log,
        "1.0\tA\tScan::Port_Scan\tFirst scan\t10.0.0.1\t10.0.0.2\t22",
    )

    first = service.get_alerts(session)
    repeated = service.get_alerts(session)

    append_notices(
        log,
        "2.0\tB\tScan::Address_Scan\tSecond scan\t10.0.0.3\t-\t445",
    )

    updated = service.get_alerts(session)

    assert len(first.value) == 1
    assert len(repeated.value) == 1
    assert len(updated.value) == 2
    assert [alert.timestamp for alert in updated.value] == ["1.0", "2.0"]


def test_disabled_alerting_discards_new_notices(tmp_path):
    session = make_session(tmp_path, "one")
    log = session.zeek_directory / "notice.log"
    log.write_text(NOTICE_HEADER, encoding="utf-8")

    service = AlertService()

    append_notices(
        log,
        "1.0\tA\tScan::Port_Scan\tDisabled scan\t10.0.0.1\t10.0.0.2\t22",
    )

    disabled_result = service.get_alerts(session)

    service.set_enabled(session, True)
    enabled_result = service.get_alerts(session)

    append_notices(
        log,
        "2.0\tB\tScan::Address_Scan\tEnabled scan\t10.0.0.3\t-\t445",
    )

    updated = service.get_alerts(session)

    assert disabled_result.value == []
    assert enabled_result.value == []
    assert len(updated.value) == 1
    assert updated.value[0].message == "Enabled scan"


def test_alerts_are_isolated_between_sessions(tmp_path):
    first = make_session(tmp_path, "first")
    second = make_session(tmp_path, "second")

    first_log = first.zeek_directory / "notice.log"
    second_log = second.zeek_directory / "notice.log"

    first_log.write_text(NOTICE_HEADER, encoding="utf-8")
    second_log.write_text(NOTICE_HEADER, encoding="utf-8")

    append_notices(
        first_log,
        "1.0\tA\tScan::Port_Scan\tFirst session\t10.0.0.1\t-\t22",
    )
    append_notices(
        second_log,
        "2.0\tB\tScan::Address_Scan\tSecond session\t10.0.0.2\t-\t445",
    )

    service = AlertService()
    service.set_enabled(first, True)
    service.set_enabled(second, True)

    first_result = service.get_alerts(first)
    second_result = service.get_alerts(second)

    assert len(first_result.value) == 1
    assert len(second_result.value) == 1
    assert first_result.value[0].session_id == "first"
    assert second_result.value[0].session_id == "second"
    assert first_result.value[0].message == "First session"
    assert second_result.value[0].message == "Second session"


def test_rejects_invalid_session_and_enabled_value(tmp_path):
    session = make_session(tmp_path, "one")
    service = AlertService()

    invalid_session = service.set_enabled(None, True)
    invalid_value = service.set_enabled(session, "yes")
    invalid_alert_query = service.get_alerts(None)

    assert invalid_session.status is Status.INVALID_INPUT
    assert invalid_value.status is Status.INVALID_INPUT
    assert invalid_alert_query.status is Status.INVALID_INPUT

def test_alerts_are_sorted_by_priority_then_timestamp(tmp_path):
    session = make_session(tmp_path, "priority")
    log = session.zeek_directory / "notice.log"
    log.write_text(NOTICE_HEADER, encoding="utf-8")

    append_notices(
        log,
        "100.0\tA\tScan::Random_Scan\tRandom scan\t10.0.0.1\t-\t-",
        "200.0\tB\tScan::Address_Scan\tAddress scan\t10.0.0.2\t-\t-",
        "50.0\tC\tScan::Port_Scan\tPort scan\t10.0.0.3\t-\t22",
    )

    service = AlertService()
    service.set_enabled(session, True)

    result = service.get_alerts(session)

    assert result.status is Status.OK
    assert [alert.priority for alert in result.value] == [
        "HIGH",
        "MEDIUM",
        "LOW",
    ]
    assert [alert.timestamp for alert in result.value] == [
        "50.0",
        "200.0",
        "100.0",
    ]


def test_alert_service_uses_synthetic_notice_fixture(tmp_path, sample_zeek_logs):
    session = make_session(tmp_path, "fixture")
    shutil.copyfile(
        sample_zeek_logs / "notice.log", session.zeek_directory / "notice.log"
    )
    service = AlertService()
    assert service.set_enabled(session, True).status is Status.OK

    result = service.get_alerts(session)

    assert result.status is Status.OK
    assert [(alert.note, alert.priority) for alert in result.value] == [
        ("Scan::Port_Scan", "HIGH"),
        ("Scan::Address_Scan", "MEDIUM"),
        ("Scan::Random_Scan", "LOW"),
    ]
    assert result.value[0].message == "Synthetic port scan notice"
    assert result.value[0].source == "198.51.100.20"
    assert result.value[0].destination == "203.0.113.8"