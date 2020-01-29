import functools

import eth_utils
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
    BlockSpecification,
    Iterable,
    List,
    Optional,
    T_BlockHash,
    TokenAddress,
    Union,
)


def address_checksum_and_decode(addr: str) -> Address:
    """ Accepts a string address and turns it into binary.

        Makes sure that the string address provided starts is 0x prefixed and
        checksummed according to EIP55 specification
    """
    if not is_0x_prefixed(addr):
        raise InvalidChecksummedAddress("Address must be 0x prefixed")

    if not is_checksum_address(addr):
        raise InvalidChecksummedAddress("Address must be EIP55 checksummed")

    return to_canonical_address(addr)


def pex(data: bytes) -> str:
    return remove_0x_prefix(encode_hex(data))[:8]


def lpex(lst: Iterable[bytes]) -> List[str]:
    return [pex(l) for l in lst]


def optional_address_to_string(
    address: Optional[Union[Address, TokenAddress]] = None,
) -> Optional[str]:
    if address is None:
        return None

    return to_checksum_address(address)


# to_checksum_address is slow, so let's cache the last 1000 results
to_checksum_address = functools.lru_cache(maxsize=1000)(eth_utils.to_checksum_address)


def format_block_id(block_id: BlockSpecification) -> str:
    """ Formats a block identifier to a string. """
    # Got a block hash
    if isinstance(block_id, T_BlockHash):
        return encode_hex(block_id)

    return str(block_id)
