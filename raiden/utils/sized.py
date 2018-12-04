from abc import ABCMeta
from collections.abc import Sized
from typing import Type, Union, _tp_cache
from eth_utils import encode_hex, is_checksum_address, to_bytes, to_checksum_address


class SizedMeta(Sized, ABCMeta):
    @_tp_cache  # can be replaced by our own cache if someone doesn't like re-using typing's
    def __getitem__(cls: Type, size: int) -> Type:
        assert size > 0, 'Subclasses need a positive size'

        class Meta(SizedMeta):
            def __len__(cls):
                return size

        return Meta(
            f'{cls.__name__}[{size}]',
            (cls,),
            {'__len__': lambda self: size},
        )

    def __len__(cls) -> int:
        """ Type length (len of bytes representation) for introspection

        len(type)==0 mean we're on the superclass. e.g. UInt
        len(type)>0 mean we're on a sized subclass. e.g. UInt[8]
        """
        return 0


class UInt(int, metaclass=SizedMeta):
    """ Int subclass which supports size assignment and ranges validation (raises ValueError)

    e.g. UInt[32] == 256bit uint
    Supports smart cast to and from bytes, and from 0x-hex-encoded strings
    """

    def __new__(cls, v: Union[bytes, str, int]):
        if isinstance(v, bytes):
            # easy construction from bytes
            v = int.from_bytes(v, byteorder='big', signed=False)
        elif isinstance(v, str) and v.startswith('0x'):
            # construct from hex-encoded strings
            v = int(v, 16)
        elif isinstance(v, str):
            # compatibility with decimal-encoded strings
            v = int(v)
        size = len(cls)
        if size:
            # if on a sized subclass, verify range
            m = 2 ** (size * 8)
            if not 0 <= v < m:
                raise ValueError(f'Invalid range. v={v}, max={m - 1}')
        return super(UInt, cls).__new__(cls, v)

    def __bytes__(self):
        """ Support bytes() cast, respecting length """
        return self.to_bytes(len(self), byteorder='big')

    def __repr__(self) -> str:
        """ Nice repr including class name and size, if present """
        return f'{self.__class__.__name__}({int.__repr__(self)})'


class Bytes(bytes, metaclass=SizedMeta):
    """ Sized bytes subclass with nice hex-encoded repr. str() is hex-encoded """
    def __new__(cls, v: Union[bytes, str]):
        if isinstance(v, str):
            v = to_bytes(hexstr=v)
        size = len(cls)
        if size and len(v) != size:
            # if on a sized subclass, verify data size
            raise ValueError(f'Invalid size. {v!r} should be of size {size}')
        return super(Bytes, cls).__new__(cls, v)

    def __repr__(self) -> str:
        """ Repr including classname and size, and string representation """
        return f'{self.__class__.__name__}({self!s})'

    def __str__(self) -> str:
        """ Standard str() cast is 0x-prefixed encoding, also supported by constructor """
        return encode_hex(self)

    def __add__(self, y: bytes) -> 'Bytes':
        """ Support returning non-sized Bytes object when concatenating """
        return Bytes(bytes.__add__(self, y))

    def __getitem__(self, item) -> 'Bytes':
        """ Support returning non-sized Bytes object when slicing """
        return Bytes(bytes.__getitem__(self, item))


class Address(Bytes[20]):
    """ 20-byte address. str() is checksum """
    def __new__(cls, v: Union[bytes, str]):
        """ Add subclass-specific validations """
        if isinstance(v, str) and not is_checksum_address(v):
            # same checks as bytes, plus checksum validation when constructing from string
            raise ValueError(f'Invalid checksum address: {v!r}')
        return super(Address, cls).__new__(cls, v)

    def __str__(self) -> str:
        """ For addresses, str() cast gives checksummed encoding """
        return to_checksum_address(self)


class TargetAddress(Address):
    pass
