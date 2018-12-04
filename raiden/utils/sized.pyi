from abc import ABCMeta
from collections.abc import Sized
from typing import Union


# helper classes
class SizedMeta(Sized, ABCMeta):
    def __len__(cls) -> int:
        ...


class UInt(int, Sized, metaclass=SizedMeta):
    def __init__(self, v: Union[bytes, str, int]) -> None:
        ...

    def __len__(self) -> int:
        ...

    def __bytes__(self) -> bytes:
        ...


class Bytes(bytes, metaclass=SizedMeta):
    def __init__(self, v: Union[bytes, str]) -> None:
        ...

    def __str__(self) -> str:
        ...

    def __add__(self, y: bytes) -> 'Bytes':
        ...

    def __getitem__(self, item):
        ...


# final classes
class Address(Bytes): ...


class TargetAddress(Address): ...