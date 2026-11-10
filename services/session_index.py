import json
import os
import stat
import sys
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from core.types import Result, Status

INDEX_FILENAME = "index.json"
INDEX_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class SessionRecord:
    session_id: str
    interface_name: str
    started_at: datetime
    ended_at: datetime
    pcap_path: Path
    zeek_directory: Path
    zeek_log_paths: tuple[Path, ...]


class SessionIndex:
    """Atomic, local JSON index for completed capture sessions."""

    def __init__(self, session_root: Path) -> None:
        self._session_root = Path(session_root)
        self._index_path = self._session_root / INDEX_FILENAME
        self._lock = threading.RLock()

    @property
    def index_path(self) -> Path:
        return self._index_path

    def list_sessions(self) -> Result[list[SessionRecord]]:
        with self._lock:
            try:
                return Result(Status.OK, self._read_records())
            except PermissionError as error:
                return Result(
                    Status.PERMISSION_ERROR,
                    detail=f"Permission denied while reading session index {self._index_path}: {error}",
                )
            except (OSError, TypeError, ValueError) as error:
                return Result(
                    Status.IO_ERROR,
                    detail=f"Could not read session index {self._index_path}: {error}",
                )

    def add_completed_session(self, record: SessionRecord) -> Result[None]:
        with self._lock:
            try:
                self._validate_record(record)
                records = self._read_records()
                if any(
                    existing.session_id == record.session_id
                    for existing in records
                ):
                    self._sync_directory()
                    return Result(Status.OK)
                records.append(self._absolute_paths(record))
                self._write_records(records)
            except PermissionError as error:
                return Result(
                    Status.PERMISSION_ERROR,
                    detail=f"Permission denied while updating session index {self._index_path}: {error}",
                )
            except (OSError, TypeError, ValueError) as error:
                return Result(
                    Status.IO_ERROR,
                    detail=f"Could not update session index {self._index_path}: {error}",
                )
            return Result(Status.OK)

    def _read_records(self) -> list[SessionRecord]:
        if self._index_path.is_symlink():
            raise ValueError("the index file must not be a symbolic link")
        if not self._index_path.exists():
            return []

        mode = self._index_path.stat().st_mode
        if not stat.S_ISREG(mode):
            raise ValueError("the index path is not a regular file")
        self._index_path.chmod(0o600)

        data = json.loads(self._index_path.read_text(encoding="utf-8"))
        if (
            not isinstance(data, dict)
            or type(data.get("version")) is not int
            or data["version"] != INDEX_SCHEMA_VERSION
            or not isinstance(data.get("sessions"), list)
        ):
            raise ValueError("unsupported or malformed session index schema")

        records: list[SessionRecord] = []
        seen_ids: set[str] = set()
        for item in data["sessions"]:
            record = self._record_from_json(item)
            if record.session_id in seen_ids:
                raise ValueError(
                    f"duplicate session ID {record.session_id!r} in session index"
                )
            seen_ids.add(record.session_id)
            records.append(record)
        return records

    def _record_from_json(self, item: object) -> SessionRecord:
        if not isinstance(item, dict):
            raise ValueError("session index entries must be objects")

        session_id = self._required_string(item, "session_id")
        interface_name = self._required_string(item, "interface_name")
        pcap_path = Path(self._required_string(item, "pcap_path"))
        zeek_directory = Path(self._required_string(item, "zeek_directory"))
        raw_log_paths = item.get("zeek_log_paths")
        if not isinstance(raw_log_paths, list) or not all(
            isinstance(path, str) and path for path in raw_log_paths
        ):
            raise ValueError("zeek_log_paths must be a list of non-empty paths")

        started_at = self._parse_timestamp(item, "started_at")
        ended_at = self._parse_timestamp(item, "ended_at")
        if ended_at < started_at:
            raise ValueError("ended_at must not precede started_at")

        record = SessionRecord(
            session_id=session_id,
            interface_name=interface_name,
            started_at=started_at,
            ended_at=ended_at,
            pcap_path=pcap_path,
            zeek_directory=zeek_directory,
            zeek_log_paths=tuple(Path(path) for path in raw_log_paths),
        )
        self._validate_record(record)
        return record

    def _write_records(self, records: list[SessionRecord]) -> None:
        self._ensure_private_directory()
        payload = {
            "version": INDEX_SCHEMA_VERSION,
            "sessions": [self._record_to_json(record) for record in records],
        }
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".index-", suffix=".tmp", dir=self._session_root
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as index_file:
                json.dump(payload, index_file, indent=2, sort_keys=True)
                index_file.write("\n")
                index_file.flush()
                os.fsync(index_file.fileno())
            temporary_path.chmod(0o600)
            os.replace(temporary_path, self._index_path)
            self._index_path.chmod(0o600)
            self._sync_directory()
        finally:
            if temporary_path.exists():
                temporary_path.unlink()

    def _ensure_private_directory(self) -> None:
        self._session_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not self._session_root.is_dir():
            raise NotADirectoryError(f"{self._session_root} is not a directory")
        self._session_root.chmod(0o700)

    def _sync_directory(self) -> None:
        if not sys.platform.startswith("linux"):
            return
        descriptor = os.open(self._session_root, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _record_to_json(self, record: SessionRecord) -> dict[str, object]:
        return {
            "session_id": record.session_id,
            "interface_name": record.interface_name,
            "started_at": record.started_at.isoformat(),
            "ended_at": record.ended_at.isoformat(),
            "pcap_path": str(record.pcap_path),
            "zeek_directory": str(record.zeek_directory),
            "zeek_log_paths": [str(path) for path in record.zeek_log_paths],
        }

    def _absolute_paths(self, record: SessionRecord) -> SessionRecord:
        return SessionRecord(
            session_id=record.session_id,
            interface_name=record.interface_name,
            started_at=record.started_at,
            ended_at=record.ended_at,
            pcap_path=record.pcap_path.resolve(),
            zeek_directory=record.zeek_directory.resolve(),
            zeek_log_paths=tuple(path.resolve() for path in record.zeek_log_paths),
        )

    def _validate_record(self, record: SessionRecord) -> None:
        if not isinstance(record, SessionRecord):
            raise TypeError("record must be a SessionRecord")
        if not record.session_id or not record.interface_name:
            raise ValueError("session_id and interface_name must not be empty")
        if not isinstance(record.pcap_path, Path) or not isinstance(
            record.zeek_directory, Path
        ):
            raise TypeError("session file locations must be paths")
        if not isinstance(record.zeek_log_paths, tuple) or not all(
            isinstance(path, Path) for path in record.zeek_log_paths
        ):
            raise TypeError("zeek_log_paths must be a tuple of paths")
        for timestamp in (record.started_at, record.ended_at):
            if not isinstance(timestamp, datetime):
                raise TypeError("session timestamps must be datetime values")
            if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                raise ValueError("session timestamps must include a timezone")
        if record.ended_at < record.started_at:
            raise ValueError("ended_at must not precede started_at")

    def _required_string(self, item: dict[str, object], key: str) -> str:
        value = item.get(key)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{key} must be a non-empty string")
        return value

    def _parse_timestamp(self, item: dict[str, object], key: str) -> datetime:
        value = datetime.fromisoformat(self._required_string(item, key))
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(f"{key} must include a timezone")
        return value
