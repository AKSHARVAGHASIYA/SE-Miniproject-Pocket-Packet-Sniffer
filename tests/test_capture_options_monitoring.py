import subprocess
import threading

import pytest

from core.types import Result, Status
from services.capture_service import (
    MAX_CAPTURE_DURATION_SECONDS,
    CaptureService,
    validate_duration,
    validate_protocol_filter,
)


class FakeProcess:
    def __init__(self, args):
        self.args = args
        self.returncode = None
        self.signals = []

    def poll(self):
        return self.returncode

    def send_signal(self, signal):
        self.signals.append(signal)
        self.returncode = 0

    def wait(self, timeout=None):
        return self.returncode

    def terminate(self):
        self.returncode = 0

    def kill(self):
        self.returncode = -9


class FakeProcessFactory:
    def __init__(self):
        self.calls = []
        self.processes = []

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        process = FakeProcess(args)
        self.processes.append(process)
        return process


def make_service(tmp_path, *, carrier=lambda _: True, clock=lambda: 0, notifier=None):
    factory = FakeProcessFactory()
    service = CaptureService(
        interface_discoverer=lambda: ["eth0"],
        interface_up_checker=lambda _: True,
        interface_carrier_checker=carrier,
        session_root=tmp_path / "sessions",
        executable_locator=lambda name: f"/usr/bin/{name}",
        process_factory=factory,
        event_notifier=notifier,
        clock=clock,
        monitor_interval_seconds=3600,
    )
    return service, factory


@pytest.mark.parametrize(
    "value",
    [0, -1, True, "1.5", " 3", "3 ", "tcp", MAX_CAPTURE_DURATION_SECONDS + 1],
)
def test_invalid_durations_are_rejected_before_commands_launch(tmp_path, value):
    service, factory = make_service(tmp_path)

    result = service.start_capture("eth0", duration=value)

    assert result.status is Status.INVALID_INPUT
    assert factory.calls == []


@pytest.mark.parametrize("value", ["tcp and port 80", "arp", "; rm -rf /", "TCP ", 1])
def test_unsafe_protocol_filters_are_rejected_before_commands_launch(tmp_path, value):
    service, factory = make_service(tmp_path)

    result = service.start_capture("eth0", protocol_filter=value)

    assert result.status is Status.INVALID_INPUT
    assert factory.calls == []


def test_valid_options_are_normalized_and_applied_to_both_passive_readers(tmp_path):
    service, factory = make_service(tmp_path)

    result = service.start_capture("eth0", duration="10", protocol_filter="TCP")

    assert result.status is Status.OK
    assert result.value.duration_seconds == 10
    assert result.value.protocol_filter == "tcp"
    zeek_args, zeek_kwargs = factory.calls[0]
    tcpdump_args, tcpdump_kwargs = factory.calls[1]
    assert zeek_args[-4:] == ["-f", "tcp", "-C", str(service._zeek_policy_path)]
    assert tcpdump_args[-1] == "tcp"
    assert zeek_kwargs["shell"] is False
    assert tcpdump_kwargs["shell"] is False
    assert service.stop_capture(result.value.session_id) is Status.OK


def test_duration_expiry_notifies_then_finalizes_and_indexes(tmp_path):
    now = [0.0]
    notifications = []
    service, _ = make_service(
        tmp_path, clock=lambda: now[0], notifier=notifications.append
    )
    started = service.start_capture("eth0", duration=5)
    now[0] = 5.0

    service._monitor_once(started.value.session_id)

    assert any("duration expired" in message.lower() for message in notifications)
    indexed = service.list_completed_sessions()
    assert indexed.status is Status.OK
    assert [record.session_id for record in indexed.value] == [started.value.session_id]
    assert started.value.pcap_path.is_file()


@pytest.mark.parametrize(
    ("interfaces", "carrier", "expected"),
    [([], lambda _: True, "removed"), (["eth0"], lambda _: False, "link loss")],
)
def test_interface_removal_and_link_loss_notify_and_keep_partial_pcap(
    tmp_path, interfaces, carrier, expected
):
    notifications = []
    service, _ = make_service(tmp_path, carrier=carrier, notifier=notifications.append)
    started = service.start_capture("eth0")
    started.value.pcap_path.write_bytes(b"partial pcap")
    service._interface_discoverer = lambda: interfaces

    service._monitor_once(started.value.session_id)

    assert any(expected in message.lower() for message in notifications)
    assert started.value.pcap_path.read_bytes() == b"partial pcap"
    assert service.list_completed_sessions().status is Status.OK


def test_unexpected_process_exit_is_distinguished_and_index_failure_can_retry(tmp_path, monkeypatch):
    notifications = []
    service, factory = make_service(tmp_path, notifier=notifications.append)
    started = service.start_capture("eth0")
    original_add = service._session_index.add_completed_session
    monkeypatch.setattr(
        service._session_index,
        "add_completed_session",
        lambda _: Result(Status.IO_ERROR, detail="simulated index failure"),
    )
    factory.processes[1].returncode = 17

    service._monitor_once(started.value.session_id)

    assert any("tcpdump exited unexpectedly" in message.lower() for message in notifications)
    assert "simulated index failure" in service.last_error
    monkeypatch.setattr(service._session_index, "add_completed_session", original_add)
    assert service.stop_capture(started.value.session_id) is Status.OK


def test_concurrent_manual_and_automatic_stop_do_not_duplicate_indexing(tmp_path):
    service, _ = make_service(tmp_path)
    started = service.start_capture("eth0")
    statuses = []
    threads = [
        threading.Thread(
            target=lambda: statuses.append(service.stop_capture(started.value.session_id))
        )
        for _ in range(2)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)

    assert not any(thread.is_alive() for thread in threads)
    assert statuses.count(Status.OK) == 1
    assert len(service.list_completed_sessions().value) == 1


def test_validation_helpers_document_the_permitted_inputs():
    assert validate_duration("60").value == 60
    assert validate_protocol_filter("ICMP").value == "icmp"

