from pathlib import Path
import socket

import pytest

from core.types import Status
from services.capture_service import CaptureService, interface_is_up


@pytest.mark.parametrize(
    ("flags", "expected_up"),
    [("0x1003", True), ("0x1002", False)],
)
def test_interface_is_up_reads_the_administrative_up_flag(
    monkeypatch, flags, expected_up
):
    monkeypatch.setattr(Path, "read_text", lambda self, encoding: flags)

    assert interface_is_up("eth0") is expected_up


def test_list_interfaces_returns_available_interfaces(monkeypatch):
    monkeypatch.setattr(
        socket, "if_nameindex", lambda: [(1, "lo"), (2, "eth0")]
    )

    result = CaptureService().list_interfaces()

    assert result.status is Status.OK
    assert result.value == ["lo", "eth0"]


def test_list_interfaces_handles_empty_interface_list():
    result = CaptureService(interface_discoverer=lambda: []).list_interfaces()

    assert result.status is Status.OK
    assert result.value == []


def test_validate_interface_accepts_available_interface():
    service = CaptureService(
        interface_discoverer=lambda: ["eth0", "wlan0"],
        interface_up_checker=lambda _: True,
    )

    result = service.validate_interface("wlan0")

    assert result.status is Status.OK
    assert result.value is None


def test_validate_interface_rejects_interface_that_is_down():
    service = CaptureService(
        interface_discoverer=lambda: ["eth0"],
        interface_up_checker=lambda _: False,
    )

    result = service.validate_interface("eth0")

    assert result.status is Status.INTERFACE_UNAVAILABLE
    assert "not up" in result.detail


def test_validate_interface_rejects_unavailable_interface():
    service = CaptureService(interface_discoverer=lambda: ["eth0"])

    result = service.validate_interface("wlan0")

    assert result.status is Status.INTERFACE_UNAVAILABLE
    assert "wlan0" in result.detail


@pytest.mark.parametrize("interface_name", ["", "  ", " eth0", "eth0 "])
def test_validate_interface_rejects_invalid_name(interface_name):
    service = CaptureService(interface_discoverer=lambda: ["eth0"])

    result = service.validate_interface(interface_name)

    assert result.status is Status.INVALID_INPUT


def test_interface_discovery_errors_return_error_results():
    def fail_discovery():
        raise OSError("interface enumeration failed")

    service = CaptureService(interface_discoverer=fail_discovery)

    listing_result = service.list_interfaces()
    validation_result = service.validate_interface("eth0")

    assert listing_result.status is Status.INTERNAL_ERROR
    assert listing_result.value is None
    assert "interface enumeration failed" in listing_result.detail
    assert validation_result.status is Status.INTERNAL_ERROR
    assert "interface enumeration failed" in validation_result.detail


def test_interface_state_discovery_errors_return_error_result():
    def fail_state_check(_):
        raise OSError("could not read interface flags")

    service = CaptureService(
        interface_discoverer=lambda: ["eth0"],
        interface_up_checker=fail_state_check,
    )

    result = service.validate_interface("eth0")

    assert result.status is Status.INTERNAL_ERROR
    assert "could not read interface flags" in result.detail
