"""Session-scoped alerts derived from supported Zeek notice records."""

from collections.abc import Callable
from dataclasses import dataclass

from core.types import Result, Status
from services.capture_service import CaptureSession
from services.log_reader import LogReader

SUPPORTED_NOTICES = frozenset({
    "Scan::Address_Scan",
    "Scan::Port_Scan",
    "Scan::Random_Scan",
})


@dataclass(frozen=True)
class Alert:
    """A supported Zeek detection notice."""

    session_id: str
    timestamp: str | None
    note: str
    message: str
    source: str | None
    destination: str | None
    port: str | None


class AlertService:
    """Collect supported Zeek notices independently for each capture session."""

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
        """Enable or disable alert collection for one session."""
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
        """Return whether alerting is enabled for this session."""
        if not isinstance(session, CaptureSession):
            return False
        return self._enabled.get(session.session_id, False)

    def get_alerts(self, session: CaptureSession) -> Result[list[Alert]]:
        """Read new notices and return this session's supported alerts."""
        if not isinstance(session, CaptureSession):
            return Result(
                status=Status.INVALID_INPUT,
                detail="A capture session is required.",
            )

        result = self._reader.read(session, ["notice"])
        if result.status is not Status.OK:
            return Result(status=result.status, detail=result.detail)

        session_alerts = self._alerts.setdefault(session.session_id, [])

        # Always advance the notice reader, even while disabled. This prevents
        # old notices from appearing later when alerting is re-enabled.
        if self.is_enabled(session):
            for record in result.value or []:
                fields = record.fields
                note = fields.get("note")

                if note not in SUPPORTED_NOTICES:
                    continue

                session_alerts.append(
                    Alert(
                        session_id=session.session_id,
                        timestamp=fields.get("ts"),
                        note=note,
                        message=fields.get("msg") or "",
                        source=fields.get("src"),
                        destination=fields.get("dst"),
                        port=fields.get("p"),
                    )
                )

        return Result(
            status=Status.OK,
            value=list(session_alerts),
            detail=result.detail,
        )
