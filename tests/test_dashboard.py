from dataclasses import dataclass
from pathlib import Path

from core.types import Result, Status, Summary
from dashboard import Dashboard


@dataclass
class FakeSession:
    session_id: str = "s1"
    interface_name: str = "eth0"


class FakeCapture:
    def __init__(self):
        self.session = FakeSession()
        self.stopped = []

    def list_interfaces(self):
        return Result(Status.OK, ["eth0"])

    def start_capture(self, interface):
        return Result(Status.OK, self.session) if interface == "eth0" else Result(Status.INTERFACE_UNAVAILABLE, detail="not available")

    def stop_capture(self, session_id):
        self.stopped.append(session_id)
        return Status.OK


class FakeSummary:
    def get_summary(self, session):
        return Result(Status.OK, Summary({"tcp": 1}, [("10.0.0.1", 1)], 1, None))


def test_dashboard_guides_user_through_capture_summary_and_safe_stop():
    answers = iter(["1", "2", "eth0", "3", "4", "3", "5"])
    output = []
    capture = FakeCapture()
    Dashboard(capture, FakeSummary(), lambda _: next(answers), output.append).run()

    text = "\n".join(output)
    assert "Available interfaces: eth0" in text
    assert "Capture started" in text
    assert "Top talkers" in text
    assert "first host above is the top talker" in text
    assert text.count("Traffic summary") == 3  # live view, final view, post-stop view
    assert capture.stopped == ["s1"]


def test_dashboard_empty_and_invalid_choices_do_not_require_hardware():
    answers = iter(["9", "3", "5"])
    output = []
    Dashboard(FakeCapture(), FakeSummary(), lambda _: next(answers), output.append).run()

    text = "\n".join(output)
    assert "choose an option" in text
    assert "No session is selected" in text
