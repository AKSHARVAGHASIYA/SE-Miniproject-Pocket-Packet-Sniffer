"""Incremental reader for Zeek's tab-separated ASCII log files.

Each ``LogReader`` owns its cursors.  It is therefore intentionally safe for
the dashboard and alert services to create separate readers for the same
capture session: reading records never removes them from the log or advances a
different consumer's cursor.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from core.types import Result, Status
from services.capture_service import CaptureSession

DEFAULT_LOG_NAMES = ("conn", "notice")


@dataclass(frozen=True)
class ZeekLogRecord:
    """One decoded Zeek ASCII record, retaining its session and log source."""

    session_id: str
    log_name: str
    fields: Mapping[str, str | None]


@dataclass
class _Cursor:
    offset: int = 0
    file_identity: tuple[int, int] | None = None
    separator: str = "\t"
    empty_field: str = "(empty)"
    unset_field: str = "-"
    field_names: list[str] | None = None
    tail: bytes = b""

    def reset(self) -> None:
        self.offset = 0
        self.file_identity = None
        self.separator = "\t"
        self.empty_field = "(empty)"
        self.unset_field = "-"
        self.field_names = None
        self.tail = b""


class LogReader:
    """Read only complete, newly appended records from a capture's Zeek logs.

    ``read`` accepts bare log stems (``"conn"``) or filenames
    (``"conn.log"``).  A log that Zeek has not created yet and a log with no
    complete new records both produce an empty ``OK`` result.  Failures reading
    an existing file produce ``IO_ERROR``.  Malformed complete lines are
    skipped; their count is included in ``Result.detail``.
    """

    def __init__(self) -> None:
        self._cursors: dict[tuple[str, Path], _Cursor] = {}

    def read(
        self, session: CaptureSession, log_names: Iterable[str] = DEFAULT_LOG_NAMES
    ) -> Result[list[ZeekLogRecord]]:
        """Return newly completed records from the requested logs in order."""
        records: list[ZeekLogRecord] = []
        malformed = 0

        for log_name in log_names:
            normalised = self._normalise_log_name(log_name)
            if normalised is None:
                return Result(
                    status=Status.INVALID_INPUT,
                    detail=f"Invalid Zeek log name: {log_name!r}",
                )

            result, skipped = self._read_one(session, normalised)
            malformed += skipped
            if result.status is Status.NOT_FOUND:
                # Zeek creates logs only after it observes relevant traffic.
                continue
            if result.status is not Status.OK:
                return Result(status=result.status, detail=result.detail)
            records.extend(result.value or [])

        detail = ""
        if malformed:
            detail = f"Skipped {malformed} malformed Zeek record(s)."
        return Result(status=Status.OK, value=records, detail=detail)

    def _read_one(
        self, session: CaptureSession, log_name: str
    ) -> tuple[Result[list[ZeekLogRecord]], int]:
        path = session.zeek_directory / f"{log_name}.log"
        key = (session.session_id, path.resolve(strict=False))
        cursor = self._cursors.setdefault(key, _Cursor())

        try:
            stat_result = path.stat()
        except FileNotFoundError:
            return Result(status=Status.NOT_FOUND, detail=f"Zeek log not found: {path}"), 0
        except PermissionError as error:
            return Result(status=Status.PERMISSION_ERROR, detail=str(error)), 0
        except OSError as error:
            return Result(status=Status.IO_ERROR, detail=str(error)), 0

        identity = (stat_result.st_dev, stat_result.st_ino)
        if cursor.file_identity is not None and (
            identity != cursor.file_identity or stat_result.st_size < cursor.offset
        ):
            cursor.reset()
        try:
            with path.open("rb") as log_file:
                # A file can be truncated and rewritten between polls to a
                # size greater than the old offset.  Checking the previously
                # consumed tail detects that case without rereading the log.
                if cursor.offset and cursor.tail:
                    log_file.seek(max(0, cursor.offset - len(cursor.tail)))
                    if log_file.read(len(cursor.tail)) != cursor.tail:
                        cursor.reset()
                cursor.file_identity = identity
                log_file.seek(cursor.offset)
                data = log_file.read()
        except PermissionError as error:
            return Result(status=Status.PERMISSION_ERROR, detail=str(error)), 0
        except OSError as error:
            return Result(status=Status.IO_ERROR, detail=str(error)), 0

        last_newline = data.rfind(b"\n")
        if last_newline == -1:
            return Result(status=Status.OK, value=[]), 0

        complete_data = data[: last_newline + 1]
        cursor.offset += len(complete_data)
        try:
            with path.open("rb") as log_file:
                tail_length = min(128, cursor.offset)
                log_file.seek(cursor.offset - tail_length)
                cursor.tail = log_file.read(tail_length)
        except OSError:
            # The next poll will either identify rotation/truncation or report
            # the underlying read error; the current complete records remain
            # valid.
            cursor.tail = b""
        records: list[ZeekLogRecord] = []
        malformed = 0
        for raw_line in complete_data.splitlines():
            line = raw_line.decode("utf-8", errors="replace").rstrip("\r")
            record = self._parse_line(cursor, session.session_id, log_name, line)
            if record is None:
                if line and not line.startswith("#"):
                    malformed += 1
                continue
            records.append(record)
        return Result(status=Status.OK, value=records), malformed

    @staticmethod
    def _normalise_log_name(log_name: str) -> str | None:
        if not isinstance(log_name, str):
            return None
        stem = log_name.removesuffix(".log")
        if not stem or Path(stem).name != stem or stem in {".", ".."}:
            return None
        return stem

    def _parse_line(
        self, cursor: _Cursor, session_id: str, log_name: str, line: str
    ) -> ZeekLogRecord | None:
        if line.startswith("#separator "):
            cursor.separator = self._unescape(line.partition(" ")[2])
            return None
        if line.startswith("#empty_field "):
            cursor.empty_field = self._unescape(line.partition(" ")[2])
            return None
        if line.startswith("#unset_field "):
            cursor.unset_field = self._unescape(line.partition(" ")[2])
            return None
        if line.startswith("#fields"):
            parts = line.split(cursor.separator)
            cursor.field_names = parts[1:]
            return None
        if line.startswith("#"):
            return None
        if not cursor.field_names:
            return None

        values = line.split(cursor.separator)
        if len(values) != len(cursor.field_names):
            return None
        fields = {
            name: (None if value == cursor.unset_field else "" if value == cursor.empty_field else value)
            for name, value in zip(cursor.field_names, values)
        }
        return ZeekLogRecord(session_id=session_id, log_name=log_name, fields=fields)

    @staticmethod
    def _unescape(value: str) -> str:
        # Zeek's ASCII header represents separators as e.g. ``\\x09``.
        try:
            return bytes(value, "ascii").decode("unicode_escape")
        except (UnicodeEncodeError, UnicodeDecodeError):
            return value
