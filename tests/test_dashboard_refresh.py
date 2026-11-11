import threading
import time
from pathlib import Path

from core.types import Result, Status
from dashboard import Dashboard
from services.capture_service import CaptureSession
from services.summary_service import SummaryService

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
    zeek_directory = directory / "zeek"
    zeek_directory.mkdir(parents=True)
    return CaptureSession(
        session_id,
        "eth0",
        directory,
        directory / "capture.pcap",
        zeek_directory,
    )


def append_record(log_path: Path, uid: str) -> float:
    with log_path.open("a", encoding="utf-8") as log_file:
        log_file.write(f"1\t{uid}\ttcp\t192.0.2.1\t198.51.100.2\n")
    return time.monotonic()


class FakeCapture:
    def __init__(self, session):
        self.session = session
        self.notifier = None
        self.stopped = []

    def set_event_notifier(self, notifier):
        self.notifier = notifier

    def start_capture(self, interface, duration=None, protocol_filter=None):
        return Result(Status.OK, self.session)

    def stop_capture(self, session_id):
        self.stopped.append(session_id)
        return Status.OK


def test_auto_refresh_displays_appended_record_within_two_seconds_and_keeps_menu_usable(
    tmp_path,
):
    session = make_session(tmp_path, "live-session")
    log_path = session.zeek_directory / "conn.log"
    log_path.write_text(CONN_HEADER, encoding="utf-8")
    capture = FakeCapture(session)
    output = []
    output_lock = threading.Lock()
    summary_displayed = threading.Event()
    menu_waiting = threading.Event()
    allow_exit = threading.Event()
    active_display_times = []
    menu_choices = iter(["2", "7"])
    field_answers = iter(["eth0", "", ""])
    dashboard = None

    def output_fn(message):
        with output_lock:
            output.append(message)
            if (
                "Total connections: 1" in message
                and dashboard.capture_active
            ):
                active_display_times.append(time.monotonic())
                summary_displayed.set()

    def input_fn(prompt):
        if prompt == "Select an option: ":
            choice = next(menu_choices)
            if choice == "7":
                menu_waiting.set()
                allow_exit.wait(timeout=3)
            return choice
        return next(field_answers)

    dashboard = Dashboard(
        capture,
        SummaryService(),
        input_fn,
        output_fn,
    )
    runner = threading.Thread(target=dashboard.run)
    runner.start()
    assert menu_waiting.wait(timeout=1)

    appended_at = append_record(log_path, "first")
    assert summary_displayed.wait(timeout=2)
    displayed_after = active_display_times[0] - appended_at
    assert 0 <= displayed_after <= 2
    print(f"Completed conn.log line displayed in {displayed_after:.3f}s")

    # A manual read racing the polling worker must not count the record twice.
    dashboard._view_summary()
    time.sleep(0.12)
    with output_lock:
        summaries = [line for line in output if "Total connections:" in line]
    assert summaries
    assert all("Total connections: 1" in line for line in summaries)

    allow_exit.set()
    runner.join(timeout=2)
    assert not runner.is_alive()
    assert capture.stopped == [session.session_id]
    assert dashboard._summary_refresh_thread is None


def test_auto_refresh_waits_for_complete_lines_and_handles_missing_log(tmp_path):
    session = make_session(tmp_path, "partial-session")
    output = []
    empty_summary = threading.Event()
    complete_summary = threading.Event()

    def output_fn(message):
        output.append(message)
        if "No complete conn.log records observed yet." in message:
            empty_summary.set()
        if "Total connections: 1" in message:
            complete_summary.set()

    dashboard = Dashboard(
        FakeCapture(session),
        SummaryService(),
        output_fn=output_fn,
        summary_refresh_interval_seconds=0.05,
    )
    dashboard.session = session
    dashboard.capture_active = True
    dashboard._start_summary_refresh(session)

    assert empty_summary.wait(timeout=1)
    log_path = session.zeek_directory / "conn.log"
    with log_path.open("w", encoding="utf-8") as log_file:
        log_file.write(CONN_HEADER + "1\tpartial\ttcp\t192.0.2.")
    time.sleep(0.12)
    assert not complete_summary.is_set()

    with log_path.open("a", encoding="utf-8") as log_file:
        log_file.write("1\t198.51.100.2\n")
    assert complete_summary.wait(timeout=2)
    assert not any(line.startswith("ERROR: summary:") for line in output)

    dashboard.capture_active = False
    dashboard._stop_summary_refresh()
    assert dashboard._summary_refresh_thread is None


def test_auto_refresh_reports_read_error_then_continues_with_existing_totals(tmp_path):
    session = make_session(tmp_path, "error-session")
    log_path = session.zeek_directory / "conn.log"
    log_path.write_text(
        CONN_HEADER + "1\tfirst\ttcp\t192.0.2.1\t198.51.100.2\n",
        encoding="utf-8",
    )
    real_summary = SummaryService()
    output = []
    first_summary = threading.Event()
    read_error = threading.Event()
    second_summary = threading.Event()

    class FailingOnceSummary:
        calls = 0

        def get_summary(self, capture_session):
            self.calls += 1
            if self.calls == 2:
                return Result(Status.IO_ERROR, detail="simulated log read error")
            return real_summary.get_summary(capture_session)

    def output_fn(message):
        output.append(message)
        if "Total connections: 1" in message:
            first_summary.set()
        if "ERROR: summary: simulated log read error" in message:
            read_error.set()
        if "Total connections: 2" in message:
            second_summary.set()

    dashboard = Dashboard(
        FakeCapture(session),
        FailingOnceSummary(),
        output_fn=output_fn,
        summary_refresh_interval_seconds=0.05,
    )
    dashboard.session = session
    dashboard.capture_active = True
    dashboard._start_summary_refresh(session)

    assert first_summary.wait(timeout=1)
    assert read_error.wait(timeout=1)
    append_record(log_path, "second")
    assert second_summary.wait(timeout=2)
    assert any("Total connections: 1" in line for line in output)
    assert any("ERROR: summary: simulated log read error" in line for line in output)

    dashboard.capture_active = False
    dashboard._stop_summary_refresh()


def test_refresh_worker_is_replaced_for_a_new_session_without_leaking(tmp_path):
    first_session = make_session(tmp_path, "first-session")
    second_session = make_session(tmp_path, "second-session")
    (first_session.zeek_directory / "conn.log").write_text(
        CONN_HEADER + "1\tfirst\ttcp\t192.0.2.1\t198.51.100.2\n",
        encoding="utf-8",
    )
    (second_session.zeek_directory / "conn.log").write_text(
        CONN_HEADER
        + "1\tsecond-a\tudp\t192.0.2.3\t198.51.100.4\n"
        + "2\tsecond-b\tudp\t192.0.2.3\t198.51.100.4\n",
        encoding="utf-8",
    )
    output = []
    first_summary = threading.Event()
    second_summary = threading.Event()

    def output_fn(message):
        output.append(message)
        if "Total connections: 1" in message:
            first_summary.set()
        if "Total connections: 2" in message:
            second_summary.set()

    dashboard = Dashboard(
        FakeCapture(first_session),
        SummaryService(),
        output_fn=output_fn,
        summary_refresh_interval_seconds=0.05,
    )
    dashboard.session = first_session
    dashboard.capture_active = True
    dashboard._start_summary_refresh(first_session)
    first_worker = dashboard._summary_refresh_thread
    assert first_summary.wait(timeout=1)

    dashboard._stop_summary_refresh()
    assert first_worker is not None and not first_worker.is_alive()
    dashboard.session = second_session
    dashboard.capture_active = True
    dashboard._start_summary_refresh(second_session)
    second_worker = dashboard._summary_refresh_thread
    assert second_summary.wait(timeout=1)
    assert second_worker is not first_worker

    dashboard.capture_active = False
    dashboard._stop_summary_refresh()
    assert second_worker is not None and not second_worker.is_alive()
    assert any("Total connections: 2" in line for line in output)


def test_disconnect_notification_stops_refresh_worker(tmp_path):
    session = make_session(tmp_path, "disconnect-session")
    (session.zeek_directory / "conn.log").write_text(
        CONN_HEADER, encoding="utf-8"
    )
    first_summary = threading.Event()
    output = []

    def output_fn(message):
        output.append(message)
        if "Traffic summary" in message:
            first_summary.set()

    capture = FakeCapture(session)
    dashboard = Dashboard(
        capture,
        SummaryService(),
        output_fn=output_fn,
        summary_refresh_interval_seconds=0.05,
    )
    dashboard.session = session
    dashboard.capture_active = True
    dashboard._start_summary_refresh(session)
    worker = dashboard._summary_refresh_thread
    assert first_summary.wait(timeout=1)

    capture.notifier("Link loss on interface 'eth0'; stopping capture safely.")
    dashboard._stop_summary_refresh()

    assert dashboard.capture_active is False
    assert worker is not None and not worker.is_alive()
    assert dashboard._summary_refresh_thread is None
    assert any("Link loss" in line for line in output)
