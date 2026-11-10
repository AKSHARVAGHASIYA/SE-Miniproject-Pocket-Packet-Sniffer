"""Small terminal controller for capture and PPS-04 traffic summaries."""

from collections.abc import Callable
from typing import Protocol

from core.types import Result, Status
from services.alert_service import AlertService
from services.capture_service import CaptureSession, CaptureService
from services.summary_service import SummaryService, render_summary


class CaptureController(Protocol):
    def list_interfaces(self) -> Result[list[str]]: ...

    def start_capture(self, interface_name: str) -> Result[CaptureSession]: ...

    def stop_capture(self, session_id: str) -> Status: ...


class Dashboard:
    def __init__(
        self,
        capture_service: CaptureController | None = None,
        summary_service: SummaryService | None = None,
        input_fn: Callable[[str], str] = input,
        output_fn: Callable[[str], None] = print,
        alert_service: AlertService | None = None,
    ) -> None:
        self.capture_service = capture_service or CaptureService()
        self.summary_service = summary_service or SummaryService()
        self.alert_service = alert_service or AlertService()
        self.input = input_fn
        self.output = output_fn
        self.session = None
        self.capture_active = False

    def run(self) -> None:
        self.output("Pocket Packet Sniffer - traffic dashboard")
        self.output("Choose an interface, start capture, view the summary, then stop safely.")
        while True:
            self.output(
                "\n1) List interfaces  "
                "2) Start capture  "
                "3) View summary  "
                "4) Stop capture  "
                "5) Toggle alerting  "
                "6) View alerts  "
                "7) Exit"
            )
            choice = self.input("Select an option: ").strip()
            if choice == "1":
                self._list_interfaces()
            elif choice == "2":
                self._start_capture()
            elif choice == "3":
                self._view_summary()
            elif choice == "4":
                self._stop_capture()
            elif choice == "5":
                self._toggle_alerting()
            elif choice == "6":
                self._view_alerts()
            elif choice == "7":
                if self.capture_active:
                    self.output("Stopping the active capture before exit...")
                    self._stop_capture()
                break
            else:
                self.output("ERROR: input: choose an option from 1 to 7.")

    def _list_interfaces(self) -> None:
        result = self.capture_service.list_interfaces()
        if result.status is not Status.OK:
            self.output(f"ERROR: interface: {result.detail}")
            return
        if not result.value:
            self.output("No network interfaces were found.")
            return
        self.output("Available interfaces: " + ", ".join(result.value))

    def _toggle_alerting(self) -> None:
        """Enable or disable alerting for the selected capture session."""
        if self.session is None:
            self.output("ERROR: Start a capture first.")
            return

        enabled = not self.alert_service.is_enabled(self.session)
        result = self.alert_service.set_enabled(self.session, enabled)

        if result.status is not Status.OK:
            self.output(f"ERROR: {result.detail}")
            return

        if enabled:
            self.output("Alerting enabled for this session.")
        else:
            self.output("Alerting disabled for this session.")

    def _view_alerts(self) -> None:
        """Display supported alerts for the selected capture session."""
        if self.session is None:
            self.output("ERROR: Start a capture first.")
            return

        result = self.alert_service.get_alerts(self.session)

        if result.status is not Status.OK:
            self.output(f"ERROR: {result.detail}")
            return

        alerts = result.value or []

        if not alerts:
            self.output("No supported scan alerts detected for this session.")
            return

        self.output(f"\nSupported alerts ({len(alerts)}):")

        for alert in alerts:
            self.output(
                f"[{alert.timestamp or 'Unknown time'}] "
                f"[{alert.priority}] {alert.note} | "
                f"Source: {alert.source or 'Unknown'} | "
                f"Destination: {alert.destination or 'Unknown'} | "
                f"Port: {alert.port or 'Unknown'}"
            )
            self.output(f"  Reason: {alert.reason}")

    def _start_capture(self) -> None:
        if self.capture_active:
            self.output("ERROR: a capture is already running. View or stop it first.")
            return
        interface = self.input("Interface name (use option 1 to list): ").strip()
        result = self.capture_service.start_capture(interface)
        if result.status is not Status.OK:
            self.output(f"ERROR: capture: {result.detail}")
            return
        self.session = result.value
        self.capture_active = True
        self.output(f"Capture started on {self.session.interface_name}.")
        self.output("Choose View summary regularly to see new conn.log records.")

    def _view_summary(self) -> None:
        if self.session is None:
            self.output("No session is selected. Start a capture first.")
            return
        result = self.summary_service.get_summary(self.session)
        if result.status is not Status.OK:
            self.output(f"ERROR: summary: {result.detail}")
            return
        self.output(render_summary(result.value))

    def _stop_capture(self) -> None:
        if self.session is None or not self.capture_active:
            self.output("No capture is running.")
            return
        session = self.session
        status = self.capture_service.stop_capture(session.session_id)
        if status is not Status.OK:
            detail = getattr(self.capture_service, "last_error", "")
            message = f"ERROR: capture: could not stop session ({status.value})"
            if detail:
                message += f": {detail}"
            self.output(message + ".")
            return
        self.capture_active = False
        self.output("Capture stopped safely. The final summary is:")
        result = self.summary_service.get_summary(session)
        if result.status is Status.OK:
            self.output(render_summary(result.value))
        else:
            self.output(f"ERROR: summary: {result.detail}")


if __name__ == "__main__":
    Dashboard().run()
