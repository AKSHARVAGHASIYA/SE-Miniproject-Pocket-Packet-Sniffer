"""Session-scoped prioritized alerts derived from supported Zeek notices."""

from collections.abc import Callable
from dataclasses import dataclass

from core.types import Result, Status
from services.capture_service import CaptureSession
from services.log_reader import LogReader

SUPPORTED_NOTICES = {
    "Scan::Address_Scan": ("MEDIUM", 2),
    "Scan::Port_Scan": ("HIGH", 3),
    "Scan::Random_Scan": ("LOW", 1),
}


@dataclass(frozen=True)
class Alert:
    """A supported Zeek detection notice."""

    session_id: str
    timestamp: str | None
    note: str
    reason: str
    source: str | None
    destination: str | None
    port: str | None
    priority: str

    @property
    def message(self) -> str:
        """Backward-compatible alias for the alert reason."""
        return self.reason


class AlertService:
    """Collect and prioritize supported Zeek notices per session."""

    def __init__(
        self,
        reader: LogReader | None = None,
        reader_factory: Callable[[], LogReader] = LogReader,
    ) -> None:
        self._reader = reader or reader_factory()
        self._enabled: dict[str, bool] = {}
        self._alerts: dict[str, list[Alert]] = {}

    def set_enabled(
        self, session: CaptureSession, enabled: bool
    ) -> Result[bool]:
        if not isinstance(session, CaptureSession):
            return Result(
                status=Status.INVALID_INPUT,
                detail="A capture session is required.",
            )

        if not isinstance(enabled, bool):
            return Result(
                status=Status.INVALID_INPUT,
                detail="Alerting state must be a boolean.",
            )

        self._enabled[session.session_id] = enabled
        self._alerts.setdefault(session.session_id, [])
        return Result(status=Status.OK, value=enabled)

    def is_enabled(self, session: CaptureSession) -> bool:
        if not isinstance(session, CaptureSession):
            return False
        return self._enabled.get(session.session_id, False)

    @staticmethod
    def _sort_key(alert: Alert) -> tuple[int, float]:
        priority_rank = SUPPORTED_NOTICES[alert.note][1]

        try:
            timestamp = float(alert.timestamp or 0)
        except (TypeError, ValueError):
            timestamp = 0

        return priority_rank, timestamp

    def get_alerts(self, session: CaptureSession) -> Result[list[Alert]]:
        if not isinstance(session, CaptureSession):
            return Result(
                status=Status.INVALID_INPUT,
                detail="A capture session is required.",
            )

        result = self._reader.read(session, ["notice"])
        if result.status is not Status.OK:
            return Result(status=result.status, detail=result.detail)

        session_alerts = self._alerts.setdefault(session.session_id, [])

        if self.is_enabled(session):
            for record in result.value or []:
                fields = record.fields
                note = fields.get("note")

                if note not in SUPPORTED_NOTICES:
                    continue

                priority, _ = SUPPORTED_NOTICES[note]
                session_alerts.append(
                    Alert(
                        session_id=session.session_id,
                        timestamp=fields.get("ts"),
                        note=note,
                        reason=fields.get("msg") or note,
                        source=fields.get("src"),
                        destination=fields.get("dst"),
                        port=fields.get("p"),
                        priority=priority,
                    )
                )

        ordered = sorted(
            session_alerts,
            key=self._sort_key,
            reverse=True,
        )

        return Result(
            status=Status.OK,
            value=ordered,
            detail=result.detail,
        )