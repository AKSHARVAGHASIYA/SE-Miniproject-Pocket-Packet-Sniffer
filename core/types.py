from dataclasses import dataclass
from enum import Enum
from typing import Generic, Optional, TypeVar


class Status(Enum):
    OK = "OK"
    INVALID_INPUT = "INVALID_INPUT"
    INTERFACE_UNAVAILABLE = "INTERFACE_UNAVAILABLE"
    INTERFACE_DISCONNECTED = "INTERFACE_DISCONNECTED"
    ZEEK_ERROR = "ZEEK_ERROR"
    NOT_FOUND = "NOT_FOUND"
    PERMISSION_ERROR = "PERMISSION_ERROR"
    IO_ERROR = "IO_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"


T = TypeVar("T")


@dataclass
class Result(Generic[T]):
    status: Status
    value: Optional[T] = None
    detail: str = ""
