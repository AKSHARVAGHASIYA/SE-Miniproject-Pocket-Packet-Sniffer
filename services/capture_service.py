from pathlib import Path
import socket
from typing import Callable

from core.types import Result, Status

IFF_UP = 0x1


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
    ) -> None:
        self._interface_discoverer = interface_discoverer
        self._interface_up_checker = interface_up_checker

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
