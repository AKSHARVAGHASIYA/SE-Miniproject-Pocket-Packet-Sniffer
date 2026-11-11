"""Session-scoped aggregation of Zeek connection records."""

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
import threading

from core.types import Result, Status, Summary
from services.capture_service import CaptureSession
from services.log_reader import LogReader, ZeekLogRecord

UNKNOWN = "unknown"


@dataclass
class _SessionTotals:
    protocol_breakdown: Counter[str] = field(default_factory=Counter)
    talkers: Counter[str] = field(default_factory=Counter)
    connection_count: int = 0


class SummaryService:
    """Aggregate newly appended ``conn.log`` records without rereading them.

    Each service owns its reader, so another consumer can read the same session
    independently.  A separate aggregate is retained for every session ID.
    """

    def __init__(
        self,
        reader: LogReader | None = None,
        reader_factory: Callable[[], LogReader] = LogReader,
    ) -> None:
        self._reader = reader or reader_factory()
        self._reader_factory = reader_factory
        self._totals: dict[str, _SessionTotals] = {}
        self._lock = threading.Lock()

    def get_summary(self, session: CaptureSession) -> Result[Summary]:
        """Read new conn.log records and return the current session summary."""
        if not isinstance(session, CaptureSession):
            return Result(status=Status.INVALID_INPUT, detail="A capture session is required.")

        with self._lock:
            result = self._reader.read(session, ["conn"])
            if result.status is not Status.OK:
                return Result(status=result.status, detail=result.detail)

            totals = self._totals.setdefault(session.session_id, _SessionTotals())
            for record in result.value or []:
                self._add_record(totals, record)

            summary = Summary(
                protocol_breakdown=dict(sorted(totals.protocol_breakdown.items())),
                top_talkers=sorted(totals.talkers.items(), key=lambda item: (-item[1], item[0])),
                connection_count=totals.connection_count,
                updated_at=datetime.now(timezone.utc),
            )
            return Result(status=Status.OK, value=summary, detail=result.detail)

    def reset(self, session_id: str) -> Status:
        """Forget accumulated totals for a session.

        The reader cursor is intentionally retained: reset starts a fresh
        aggregation from records appended after the reset, rather than
        unexpectedly double-counting the existing log.
        """
        with self._lock:
            if session_id not in self._totals:
                return Status.NOT_FOUND
            self._totals.pop(session_id)
            return Status.OK

    @staticmethod
    def _add_record(totals: _SessionTotals, record: ZeekLogRecord) -> None:
        protocol = record.fields.get("proto")
        protocol_name = protocol.strip().lower() if isinstance(protocol, str) and protocol.strip() else UNKNOWN
        totals.protocol_breakdown[protocol_name] += 1
        totals.connection_count += 1

        endpoints = {
            value.strip()
            for field_name in ("id.orig_h", "id.resp_h")
            if isinstance(value := record.fields.get(field_name), str) and value.strip()
        }
        for host in endpoints:
            totals.talkers[host] += 1


def render_summary(summary: Summary) -> str:
    """Render a summary with beginner-friendly interpretation guidance."""
    lines = [
        "Traffic summary",
        "===============",
        f"Total connections: {summary.connection_count}",
        "",
        "Protocol breakdown (connections by conn.log proto):",
    ]
    if summary.protocol_breakdown:
        lines.extend(f"  {protocol}: {count}" for protocol, count in summary.protocol_breakdown.items())
    else:
        lines.append("  No complete conn.log records observed yet.")

    lines.extend([
        "",
        "Top talkers (connection endpoints counted; highest first):",
    ])
    if summary.top_talkers:
        lines.extend(f"  {rank}. {host}: {count} connection(s)" for rank, (host, count) in enumerate(summary.top_talkers, 1))
        lines.extend([
            "",
            "Guidance: the first host above is the top talker for this session.",
            "This ranking counts conn.log connections involving each endpoint; it is not packet or byte volume.",
        ])
    else:
        lines.extend([
            "  No host endpoints observed yet.",
            "Guidance: start traffic and refresh the summary; the first listed host will be the top talker.",
        ])
    return "\n".join(lines)
