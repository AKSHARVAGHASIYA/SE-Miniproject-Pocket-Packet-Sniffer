from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import threading
from typing import Callable
import uuid

from core.types import Result, Status

IFF_UP = 0x1
DEFAULT_SESSION_ROOT = (
    Path.home() / ".local" / "share" / "pocket-packet-sniffer" / "sessions"
)
PROCESS_STOP_TIMEOUT = 5


@dataclass(frozen=True)
class CaptureSession:
    session_id: str
    interface_name: str
    session_directory: Path
    pcap_path: Path
    zeek_directory: Path


@dataclass
class _RunningCapture:
    session: CaptureSession
    zeek_process: subprocess.Popen
    tcpdump_process: subprocess.Popen


def interface_is_up(interface_name: str) -> bool:
    flags_path = Path("/sys/class/net") / interface_name / "flags"
    flags = int(flags_path.read_text(encoding="ascii").strip(), 16)
    return bool(flags & IFF_UP)


def discover_interfaces() -> list[str]:
    return [name for _, name in socket.if_nameindex()]


class CaptureService:
    def __init__(
        self,
        interface_discoverer: Callable[[], list[str]] = discover_interfaces,
        interface_up_checker: Callable[[str], bool] = interface_is_up,
        session_root: Path = DEFAULT_SESSION_ROOT,
        executable_locator: Callable[[str], str | None] = shutil.which,
        process_factory: Callable[..., subprocess.Popen] = subprocess.Popen,
    ) -> None:
        self._interface_discoverer = interface_discoverer
        self._interface_up_checker = interface_up_checker
        self._session_root = Path(session_root)
        self._executable_locator = executable_locator
        self._process_factory = process_factory
        self._running_captures: dict[str, _RunningCapture] = {}
        self._interface_sessions: dict[str, str] = {}
        self._lock = threading.RLock()

    def list_interfaces(self) -> Result[list[str]]:
        try:
            interfaces = self._interface_discoverer()
        except OSError as error:
            return Result(
                status=Status.INTERNAL_ERROR,
                detail=f"Could not discover network interfaces: {error}",
            )

        return Result(status=Status.OK, value=list(interfaces))

    def validate_interface(self, interface_name: str) -> Result[None]:
        if (
            not isinstance(interface_name, str)
            or not interface_name
            or interface_name != interface_name.strip()
        ):
            return Result(
                status=Status.INVALID_INPUT,
                detail="Interface name must be a non-empty name without surrounding whitespace.",
            )

        interfaces_result = self.list_interfaces()
        if interfaces_result.status is not Status.OK:
            return Result(
                status=interfaces_result.status,
                detail=interfaces_result.detail,
            )

        if interface_name not in interfaces_result.value:
            return Result(
                status=Status.INTERFACE_UNAVAILABLE,
                detail=f"Interface {interface_name!r} is not available.",
            )

        try:
            is_up = self._interface_up_checker(interface_name)
        except FileNotFoundError:
            return Result(
                status=Status.INTERFACE_UNAVAILABLE,
                detail=f"Interface {interface_name!r} is no longer available.",
            )
        except (OSError, ValueError) as error:
            return Result(
                status=Status.INTERNAL_ERROR,
                detail=f"Could not check the state of interface {interface_name!r}: {error}",
            )

        if not is_up:
            return Result(
                status=Status.INTERFACE_UNAVAILABLE,
                detail=f"Interface {interface_name!r} is not up.",
            )

        return Result(status=Status.OK)

    def start_capture(self, interface_name: str) -> Result[CaptureSession]:
        validation = self.validate_interface(interface_name)
        if validation.status is not Status.OK:
            return Result(status=validation.status, detail=validation.detail)

        with self._lock:
            if interface_name in self._interface_sessions:
                return Result(
                    status=Status.INVALID_INPUT,
                    detail=f"A capture is already running on interface {interface_name!r}.",
                )

            zeek_executable = self._executable_locator("zeek")
            if zeek_executable is None:
                return Result(
                    status=Status.ZEEK_ERROR,
                    detail="Zeek is not installed or is not available on PATH.",
                )

            tcpdump_executable = self._executable_locator("tcpdump")
            if tcpdump_executable is None:
                return Result(
                    status=Status.INTERNAL_ERROR,
                    detail="tcpdump is not installed or is not available on PATH.",
                )

            session_id = uuid.uuid4().hex
            session_directory = self._session_root / session_id
            zeek_directory = session_directory / "zeek"
            pcap_path = session_directory / "capture.pcap"
            session = CaptureSession(
                session_id=session_id,
                interface_name=interface_name,
                session_directory=session_directory,
                pcap_path=pcap_path,
                zeek_directory=zeek_directory,
            )

            zeek_process = None
            tcpdump_process = None
            try:
                self._ensure_private_directory(self._session_root)
                self._create_private_directory(session_directory)
                self._create_private_directory(zeek_directory)
                self._create_private_file(pcap_path).close()
                zeek_process = self._launch_zeek(zeek_executable, session)
                tcpdump_process = self._launch_tcpdump(tcpdump_executable, session)
            except PermissionError as error:
                failed_processes = [
                    process
                    for process in (zeek_process, tcpdump_process)
                    if process is not None
                ]
                cleanup_errors = self._stop_processes(failed_processes)
                detail = f"Permission denied while starting capture: {error}"
                if cleanup_errors:
                    detail += "; cleanup failed: " + "; ".join(cleanup_errors)
                return Result(status=Status.PERMISSION_ERROR, detail=detail)
            except OSError as error:
                failed_processes = [
                    process
                    for process in (zeek_process, tcpdump_process)
                    if process is not None
                ]
                cleanup_errors = self._stop_processes(failed_processes)
                detail = f"Could not start capture: {error}"
                if cleanup_errors:
                    detail += "; cleanup failed: " + "; ".join(cleanup_errors)
                return Result(status=Status.IO_ERROR, detail=detail)

            failed_process = self._failed_startup_process(
                zeek_process, tcpdump_process
            )
            if failed_process is not None:
                cleanup_errors = self._stop_processes(
                    [zeek_process, tcpdump_process]
                )
                detail = self._startup_error_detail(failed_process, session)
                if cleanup_errors:
                    detail += "; cleanup failed: " + "; ".join(cleanup_errors)
                status = (
                    Status.ZEEK_ERROR
                    if failed_process is zeek_process
                    else Status.IO_ERROR
                )
                return Result(status=status, detail=detail)

            self._running_captures[session_id] = _RunningCapture(
                session=session,
                zeek_process=zeek_process,
                tcpdump_process=tcpdump_process,
            )
            self._interface_sessions[interface_name] = session_id
            return Result(status=Status.OK, value=session)

    def stop_capture(self, session_id: str) -> Status:
        with self._lock:
            capture = self._running_captures.get(session_id)
            if capture is None:
                return Status.NOT_FOUND

            errors = self._stop_processes(
                [capture.tcpdump_process, capture.zeek_process]
            )
            processes_stopped = all(
                process.poll() is not None
                for process in (
                    capture.tcpdump_process,
                    capture.zeek_process,
                )
            )

            if processes_stopped:
                self._running_captures.pop(session_id, None)
                self._interface_sessions.pop(capture.session.interface_name, None)
                try:
                    self._restrict_session_files(capture.session.session_directory)
                except OSError as error:
                    errors.append(
                        f"Could not restrict session file permissions: {error}"
                    )

            if errors:
                return Status.IO_ERROR
            return Status.OK

    def _create_private_directory(self, path: Path) -> None:
        path.mkdir(mode=0o700, parents=True, exist_ok=False)
        path.chmod(0o700)

    def _ensure_private_directory(self, path: Path) -> None:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not path.is_dir():
            raise NotADirectoryError(f"{path} is not a directory")
        path.chmod(0o700)

    def _create_private_file(self, path: Path):
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        return os.fdopen(descriptor, "wb")

    def _launch_zeek(
        self, executable: str, session: CaptureSession
    ) -> subprocess.Popen:
        stdout_path = session.session_directory / "zeek.stdout.log"
        stderr_path = session.session_directory / "zeek.stderr.log"
        with self._create_private_file(stdout_path) as stdout_file:
            with self._create_private_file(stderr_path) as stderr_file:
                return self._process_factory(
                    [executable, "-i", session.interface_name, "-C"],
                    cwd=session.zeek_directory,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    shell=False,
                )

    def _launch_tcpdump(
        self, executable: str, session: CaptureSession
    ) -> subprocess.Popen:
        stderr_path = session.session_directory / "tcpdump.stderr.log"
        with self._create_private_file(stderr_path) as stderr_file:
            return self._process_factory(
                [
                    executable,
                    "-U",
                    "-n",
                    "-i",
                    session.interface_name,
                    "-w",
                    str(session.pcap_path),
                ],
                cwd=session.session_directory,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=stderr_file,
                shell=False,
            )

    def _failed_startup_process(
        self, zeek_process: subprocess.Popen, tcpdump_process: subprocess.Popen
    ) -> subprocess.Popen | None:
        if zeek_process.poll() is not None:
            return zeek_process
        if tcpdump_process.poll() is not None:
            return tcpdump_process
        return None

    def _startup_error_detail(
        self, process: subprocess.Popen, session: CaptureSession
    ) -> str:
        if process.args and Path(str(process.args[0])).name == "zeek":
            error_path = session.session_directory / "zeek.stderr.log"
            component = "Zeek"
        else:
            error_path = session.session_directory / "tcpdump.stderr.log"
            component = "tcpdump"
        try:
            output = error_path.read_text(encoding="utf-8").strip()
        except OSError:
            output = ""
        detail = f"{component} exited during startup."
        if output:
            detail += f" {output}"
        return detail

    def _stop_processes(self, processes: list[subprocess.Popen]) -> list[str]:
        errors: list[str] = []
        for process in processes:
            try:
                initial_returncode = process.poll()
                if initial_returncode is not None:
                    errors.append(
                        f"Process {process.args!r} exited before it was stopped "
                        f"(exit code {initial_returncode})."
                    )
                    continue
                try:
                    process.send_signal(signal.SIGINT)
                except ProcessLookupError:
                    pass
                except OSError as error:
                    errors.append(
                        f"Could not interrupt process {process.args!r}: {error}"
                    )
                    try:
                        process.terminate()
                    except ProcessLookupError:
                        pass
                try:
                    process.wait(timeout=PROCESS_STOP_TIMEOUT)
                except subprocess.TimeoutExpired:
                    try:
                        process.terminate()
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=PROCESS_STOP_TIMEOUT)
                    except subprocess.TimeoutExpired:
                        try:
                            process.kill()
                        except ProcessLookupError:
                            pass
                        try:
                            process.wait(timeout=PROCESS_STOP_TIMEOUT)
                        except subprocess.TimeoutExpired:
                            errors.append(
                                f"Process {process.args!r} did not exit after being killed."
                            )
            except OSError as error:
                errors.append(f"Could not stop process {process.args!r}: {error}")
                try:
                    process.kill()
                    process.wait(timeout=PROCESS_STOP_TIMEOUT)
                except (OSError, subprocess.TimeoutExpired) as cleanup_error:
                    errors.append(
                        f"Could not kill process {process.args!r}: {cleanup_error}"
                    )
        return errors

    def _restrict_session_files(self, session_directory: Path) -> None:
        session_directory.chmod(0o700)
        for path in session_directory.rglob("*"):
            if path.is_dir():
                path.chmod(0o700)
            elif path.is_file():
                path.chmod(0o600)
