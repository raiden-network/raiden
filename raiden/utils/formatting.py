from eth_hash.auto import keccak
from eth_typing import HexStr
from eth_utils import (
    encode_hex,
    is_0x_prefixed,
    is_checksum_address,
    remove_0x_prefix,
    to_canonical_address,
)

from raiden.exceptions import InvalidChecksummedAddress
from raiden.utils.typing import (
    Address,
    AddressHex,
    AddressTypes,
    BlockIdentifier,
    ChecksumAddress,
    Iterable,
    List,
    Optional,
    T_BlockHash,
    TokenAddress,
    Union,
)


def address_checksum_and_decode(addr: str) -> Address:
    """Accepts a string address and turns it into binary.

    Makes sure that the string address provided starts is 0x prefixed and
    checksummed according to EIP55 specification
    """
    if not is_0x_prefixed(addr):
        raise InvalidChecksummedAddress("Address must be 0x prefixed")

    if not is_checksum_address(addr):
        raise InvalidChecksummedAddress("Address must be EIP55 checksummed")

    return to_canonical_address(addr)


def to_checksum_address(address: AddressTypes) -> ChecksumAddress:
    """Implementation of EIP-55 checksum address.

    Adaptation of https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md#specification for
    python 3.7+.

    Refined after: https://github.com/ethereum/eips/issues/55#issuecomment-261521584

    Note: As of today (eth-utils==1.8.1), this is ~4-5 times faster than
    `eth_utils.to_checksum_address`.
    """
    out = ""
    v = int.from_bytes(keccak(bytes(address.hex(), "ascii")), byteorder="big")
    for i, char in enumerate(address.hex()):
        if char in "0123456789":
            out += char
        else:
            out += char.upper() if (v & (2 ** (255 - 4 * i))) else char.lower()
    return ChecksumAddress(AddressHex(HexStr("0x" + out)))


def pex(data: bytes) -> str:
    return remove_0x_prefix(encode_hex(data))[:8]


def lpex(lst: Iterable[bytes]) -> List[str]:
    return [pex(item) for item in lst]


def optional_address_to_string(
    address: Optional[Union[Address, TokenAddress]] = None,
) -> Optional[str]:
    if address is None:
        return None

    return to_hex_address(address)


def to_hex_address(address: AddressTypes) -> AddressHex:
    return AddressHex(HexStr("0x" + address.hex()))


def format_block_id(block_id: BlockIdentifier) -> str:
    """Formats a block identifier to a string."""
    # Got a block hash
    if isinstance(block_id, T_BlockHash):
        return encode_hex(block_id)

    return str(block_id)
