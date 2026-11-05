import os
from pathlib import Path
import signal
import stat
import subprocess

import pytest

from core.types import Status
from services.capture_service import CaptureService


class FakeProcess:
    def __init__(self, args, startup_status=None, wait_timeouts=0):
        self.args = args
        self.returncode = startup_status
        self.wait_timeouts = wait_timeouts
        self.signals = []
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def send_signal(self, received_signal):
        self.signals.append(received_signal)
        self.returncode = 0

    def wait(self, timeout=None):
        if self.wait_timeouts:
            self.wait_timeouts -= 1
            raise subprocess.TimeoutExpired(self.args, timeout)
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = 0

    def kill(self):
        self.killed = True
        self.returncode = -9


class FakeProcessFactory:
    def __init__(self, *, fail_on_call=None, startup_statuses=None):
        self.calls = []
        self.processes = []
        self.fail_on_call = fail_on_call
        self.startup_statuses = startup_statuses or []

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if len(self.calls) == self.fail_on_call:
            raise OSError("simulated process startup failure")
        status = (
            self.startup_statuses[len(self.processes)]
            if len(self.processes) < len(self.startup_statuses)
            else None
        )
        process = FakeProcess(args, startup_status=status)
        self.processes.append(process)
        return process


def make_service(tmp_path, process_factory=None, executable_locator=None):
    return CaptureService(
        interface_discoverer=lambda: ["eth0"],
        interface_up_checker=lambda _: True,
        session_root=tmp_path / "sessions",
        executable_locator=executable_locator or (lambda name: f"/usr/bin/{name}"),
        process_factory=process_factory or FakeProcessFactory(),
    )


def test_start_capture_launches_live_zeek_and_packet_buffered_pcap(tmp_path):
    process_factory = FakeProcessFactory()
    service = make_service(tmp_path, process_factory=process_factory)

    result = service.start_capture("eth0")

    assert result.status is Status.OK
    session = result.value
    assert session is not None
    assert session.pcap_path.is_file()
    assert session.zeek_directory.is_dir()
    if os.name == "posix":
        assert stat.S_IMODE(session.session_directory.stat().st_mode) == 0o700
        assert stat.S_IMODE(session.pcap_path.stat().st_mode) == 0o600

    zeek_args, zeek_options = process_factory.calls[0]
    tcpdump_args, tcpdump_options = process_factory.calls[1]
    assert zeek_args == ["/usr/bin/zeek", "-i", "eth0", "-C"]
    assert Path(zeek_options["cwd"]) == session.zeek_directory
    assert tcpdump_args == [
        "/usr/bin/tcpdump",
        "-U",
        "-n",
        "-i",
        "eth0",
        "-w",
        str(session.pcap_path),
    ]
    assert Path(tcpdump_options["cwd"]) == session.session_directory
    assert all(options["shell"] is False for _, options in process_factory.calls)

    assert service.stop_capture(session.session_id) is Status.OK
    assert all(process.signals == [signal.SIGINT] for process in process_factory.processes)
    if os.name == "posix":
        assert stat.S_IMODE(session.session_directory.stat().st_mode) == 0o700
        for path in session.session_directory.rglob("*"):
            expected_mode = 0o700 if path.is_dir() else 0o600
            assert stat.S_IMODE(path.stat().st_mode) == expected_mode


def test_start_capture_rejects_duplicate_interface_capture(tmp_path):
    process_factory = FakeProcessFactory()
    service = make_service(tmp_path, process_factory=process_factory)
    first = service.start_capture("eth0")

    second = service.start_capture("eth0")

    assert first.status is Status.OK
    assert second.status is Status.INVALID_INPUT
    assert "already running" in second.detail
    assert len(process_factory.calls) == 2
    assert service.stop_capture(first.value.session_id) is Status.OK


def test_start_capture_rejects_invalid_interface_before_launching(tmp_path):
    process_factory = FakeProcessFactory()
    service = CaptureService(
        interface_discoverer=lambda: [],
        interface_up_checker=lambda _: True,
        session_root=tmp_path / "sessions",
        executable_locator=lambda name: f"/usr/bin/{name}",
        process_factory=process_factory,
    )

    result = service.start_capture("eth0")

    assert result.status is Status.INTERFACE_UNAVAILABLE
    assert process_factory.calls == []


def test_start_capture_rejects_interface_that_is_down(tmp_path):
    process_factory = FakeProcessFactory()
    service = CaptureService(
        interface_discoverer=lambda: ["eth0"],
        interface_up_checker=lambda _: False,
        session_root=tmp_path / "sessions",
        executable_locator=lambda name: f"/usr/bin/{name}",
        process_factory=process_factory,
    )

    result = service.start_capture("eth0")

    assert result.status is Status.INTERFACE_UNAVAILABLE
    assert process_factory.calls == []


@pytest.mark.parametrize(
    ("missing_executable", "expected_status"),
    [("zeek", Status.ZEEK_ERROR), ("tcpdump", Status.INTERNAL_ERROR)],
)
def test_start_capture_reports_missing_dependencies(
    tmp_path, missing_executable, expected_status
):
    process_factory = FakeProcessFactory()
    service = make_service(
        tmp_path,
        process_factory=process_factory,
        executable_locator=lambda name: (
            None if name == missing_executable else f"/usr/bin/{name}"
        ),
    )

    result = service.start_capture("eth0")

    assert result.status is expected_status
    assert process_factory.calls == []


@pytest.mark.parametrize(
    ("fail_on_call", "expected_processes"),
    [(1, 0), (2, 1)],
)
def test_process_start_failure_cleans_up_previously_started_process(
    tmp_path, fail_on_call, expected_processes
):
    process_factory = FakeProcessFactory(fail_on_call=fail_on_call)
    service = make_service(tmp_path, process_factory=process_factory)

    result = service.start_capture("eth0")

    assert result.status is Status.IO_ERROR
    assert "simulated process startup failure" in result.detail
    assert len(process_factory.processes) == expected_processes
    assert all(
        process.signals == [signal.SIGINT] for process in process_factory.processes
    )


@pytest.mark.parametrize(
    ("startup_statuses", "expected_status"),
    [([1], Status.ZEEK_ERROR), ([None, 1], Status.IO_ERROR)],
)
def test_process_exiting_during_startup_cleans_up_other_process(
    tmp_path, startup_statuses, expected_status
):
    process_factory = FakeProcessFactory(startup_statuses=startup_statuses)
    service = make_service(tmp_path, process_factory=process_factory)

    result = service.start_capture("eth0")

    assert result.status is expected_status
    assert all(process.poll() is not None for process in process_factory.processes)


def test_stop_capture_escalates_when_process_does_not_stop_on_interrupt(tmp_path):
    process_factory = FakeProcessFactory()
    service = make_service(tmp_path, process_factory=process_factory)
    result = service.start_capture("eth0")
    process_factory.processes[0].wait_timeouts = 1

    status = service.stop_capture(result.value.session_id)

    assert status is Status.OK
    assert process_factory.processes[0].terminated
    assert not process_factory.processes[0].killed


def test_stop_capture_kills_process_after_interrupt_and_terminate_timeouts(tmp_path):
    process_factory = FakeProcessFactory()
    service = make_service(tmp_path, process_factory=process_factory)
    result = service.start_capture("eth0")
    process_factory.processes[0].wait_timeouts = 2

    status = service.stop_capture(result.value.session_id)

    assert status is Status.OK
    assert process_factory.processes[0].terminated
    assert process_factory.processes[0].killed


def test_stop_capture_returns_not_found_for_unknown_session(tmp_path):
    service = make_service(tmp_path)

    assert service.stop_capture("unknown") is Status.NOT_FOUND
