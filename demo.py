"""Run the dashboard with synthetic logs for an offline demonstration."""

import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path

from core.types import Result, Status
from dashboard import Dashboard
from services.alert_service import AlertService
from services.capture_service import CaptureSession
from services.summary_service import SummaryService

DEMO_INTERFACE = "demo0"
FIXTURE_DIRECTORY = Path(__file__).resolve().parent / "tests" / "fixtures" / "zeek"


class DemoCaptureService:
    """Provide a simulated capture session backed by the checked-in fixtures."""

    def __init__(self, session: CaptureSession) -> None:
        self.session = session
        self.active = False

    def list_interfaces(self) -> Result[list[str]]:
        return Result(status=Status.OK, value=[DEMO_INTERFACE])

    def start_capture(self, interface_name: str) -> Result[CaptureSession]:
        if interface_name != DEMO_INTERFACE:
            return Result(
                status=Status.INTERFACE_UNAVAILABLE,
                detail=f"Use the synthetic demo interface {DEMO_INTERFACE!r}.",
            )
        if self.active:
            return Result(
                status=Status.INVALID_INPUT,
                detail="A demo session is already running.",
            )
        self.active = True
        return Result(status=Status.OK, value=self.session)

    def stop_capture(self, session_id: str) -> Status:
        if session_id != self.session.session_id or not self.active:
            return Status.NOT_FOUND
        self.active = False
        return Status.OK


def run_demo(
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
) -> None:
    """Launch an interactive dashboard using the synthetic Zeek fixtures."""
    with tempfile.TemporaryDirectory(prefix="pocket-packet-sniffer-demo-") as root:
        session_directory = Path(root) / "demo-session"
        zeek_directory = session_directory / "zeek"
        zeek_directory.mkdir(parents=True)
        shutil.copyfile(FIXTURE_DIRECTORY / "conn.log", zeek_directory / "conn.log")
        shutil.copyfile(FIXTURE_DIRECTORY / "notice.log", zeek_directory / "notice.log")

        session = CaptureSession(
            session_id="demo-session",
            interface_name=DEMO_INTERFACE,
            session_directory=session_directory,
            pcap_path=session_directory / "capture.pcap",
            zeek_directory=zeek_directory,
        )
        capture_service = DemoCaptureService(session)
        output_fn("OFFLINE DEMO: synthetic fixture data only; no packets are captured.")
        output_fn("When prompted for an interface, enter demo0.")
        Dashboard(
            capture_service=capture_service,
            summary_service=SummaryService(),
            alert_service=AlertService(),
            input_fn=input_fn,
            output_fn=output_fn,
        ).run()


if __name__ == "__main__":
    run_demo()
