import socket
from typing import Callable

from core.types import Result, Status


def discover_interfaces() -> list[str]:
    return [name for _, name in socket.if_nameindex()]


class CaptureService:
    def __init__(
        self, interface_discoverer: Callable[[], list[str]] = discover_interfaces
    ) -> None:
        self._interface_discoverer = interface_discoverer

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

        return Result(status=Status.OK)
