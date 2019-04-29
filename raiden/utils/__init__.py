import collections
import os
import random
import re
import sys
import time
from itertools import zip_longest

import gevent
from eth_keys import keys
from eth_utils import (
    add_0x_prefix,
    decode_hex,
    encode_hex,
    is_0x_prefixed,
    is_checksum_address,
    remove_0x_prefix,
    to_bytes,
    to_checksum_address,
)
from web3 import Web3

import raiden
from raiden import constants
from raiden.exceptions import InvalidAddress
from raiden.utils.signing import sha3  # noqa
from raiden.utils.typing import (
    Address,
    Any,
    BlockNumber,
    BlockSpecification,
    ChainID,
    ChannelID,
    Dict,
    Host,
    HostPort,
    Iterable,
    List,
    Optional,
    Port,
    Secret,
    T_Address,
    T_BlockHash,
    T_BlockNumber,
    T_ChainID,
    T_ChannelID,
    TokenAddress,
    TokenNetworkAddress,
    TokenNetworkID,
    Tuple,
    Union,
)

# Placeholder chain ID for refactoring in scope of #3493
CHAIN_ID_UNSPECIFIED = ChainID(-1)


class CanonicalIdentifier:
    def __init__(
            self,
            chain_identifier: ChainID,
            # introducing the type as Union, to avoid casting for now.
            # Should be only `..Address` later
            token_network_address: Union[TokenNetworkAddress, TokenNetworkID],
            channel_identifier: ChannelID,
    ):
        self.chain_identifier = chain_identifier
        self.token_network_address = token_network_address
        self.channel_identifier = channel_identifier

    def __str__(self):
        return (
            f'<CanonicalIdentifier '
            f'chain_id:{self.chain_identifier} '
            f'token_network_address:{pex(self.token_network_address)} '
            f'channel_id:{self.channel_identifier}>'
        )

    def validate(self):
        if not isinstance(self.token_network_address, T_Address):
            raise ValueError('token_network_identifier must be an address instance')

        if not isinstance(self.channel_identifier, T_ChannelID):
            raise ValueError('channel_identifier must be an ChannelID instance')

        if not isinstance(self.chain_identifier, T_ChainID):
            raise ValueError('chain_id must be a ChainID instance')

        if (
                self.channel_identifier < 0 or
                self.channel_identifier > constants.UINT256_MAX
        ):
            raise ValueError('channel id is invalid')

    def to_dict(self) -> Dict[str, Any]:
        return dict(
            chain_identifier=str(self.chain_identifier),
            token_network_address=to_checksum_address(self.token_network_address),
            channel_identifier=str(self.channel_identifier),
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CanonicalIdentifier':
        return cls(
            chain_identifier=ChainID(int(data['chain_identifier'])),
            token_network_address=TokenNetworkAddress(
                to_bytes(hexstr=data['token_network_address']),
            ),
            channel_identifier=ChannelID(int(data['channel_identifier'])),
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CanonicalIdentifier):
            return NotImplemented
        return (
            self.chain_identifier == other.chain_identifier and
            self.token_network_address == other.token_network_address and
            self.channel_identifier == other.channel_identifier
        )

    def __ne__(self, other: object) -> bool:
        if not isinstance(other, CanonicalIdentifier):
            return True
        return not self.__eq__(other)


def random_secret() -> Secret:
    """ Return a random 32 byte secret except the 0 secret since it's not accepted in the contracts
    """
    while True:
        secret = os.urandom(32)
        if secret != constants.EMPTY_HASH:
            return Secret(secret)


def ishash(data: bytes) -> bool:
    return isinstance(data, bytes) and len(data) == 32


def is_minified_address(addr):
    return re.compile('(0x)?[a-f0-9]{6,8}').match(addr)


def address_checksum_and_decode(addr: str) -> Address:
    """ Accepts a string address and turns it into binary.

        Makes sure that the string address provided starts is 0x prefixed and
        checksummed according to EIP55 specification
    """
    if not is_0x_prefixed(addr):
        raise InvalidAddress('Address must be 0x prefixed')

    if not is_checksum_address(addr):
        raise InvalidAddress('Address must be EIP55 checksummed')

    addr_bytes = decode_hex(addr)
    assert len(addr_bytes) in (20, 0)
    return Address(addr_bytes)


def data_encoder(data: bytes, length: int = 0) -> str:
    data = remove_0x_prefix(encode_hex(data))
    return add_0x_prefix(
        data.rjust(length * 2, b'0').decode(),
    )


def data_decoder(data: str) -> bytes:
    assert is_0x_prefixed(data)
    return decode_hex(data)


def quantity_encoder(i: int) -> str:
    """Encode integer quantity `data`."""
    return hex(i).rstrip('L')


def pex(data: bytes) -> str:
    return remove_0x_prefix(encode_hex(data))[:8]


def lpex(lst: Iterable[bytes]) -> List[str]:
    return [pex(l) for l in lst]


def host_port_to_endpoint(host: str, port: int) -> str:
    return '{}:{}'.format(host, port)


def split_endpoint(endpoint: str) -> HostPort:
    match = re.match(r'(?:[a-z0-9]*:?//)?([^:/]+)(?::(\d+))?', endpoint, re.I)
    if not match:
        raise ValueError('Invalid endpoint', endpoint)
    host, port = match.groups()
    returned_port = None
    if port:
        returned_port = Port(int(port))
    return Host(host), returned_port


def privatekey_to_publickey(private_key_bin: bytes) -> bytes:
    """ Returns public key in bitcoins 'bin' encoding. """
    if not ishash(private_key_bin):
        raise ValueError('private_key_bin format mismatch. maybe hex encoded?')
    return keys.PrivateKey(private_key_bin).public_key.to_bytes()


def privatekey_to_address(private_key_bin: bytes) -> Address:
    return keys.PrivateKey(private_key_bin).public_key.to_canonical_address()


def get_project_root() -> str:
    return os.path.dirname(raiden.__file__)


def get_relative_path(file_name) -> str:
    prefix = os.path.commonprefix([
        os.path.realpath('.'),
        os.path.realpath(file_name),
    ])
    return file_name.replace(prefix + '/', '')


def get_system_spec() -> Dict[str, str]:
    """Collect information about the system and installation.
    """
    import pkg_resources
    import platform

    if sys.platform == 'darwin':
        system_info = 'macOS {} {}'.format(
            platform.mac_ver()[0],
            platform.architecture()[0],
        )
    else:
        system_info = '{} {} {}'.format(
            platform.system(),
            '_'.join(part for part in platform.architecture() if part),
            platform.release(),
        )

    try:
        version = pkg_resources.require(raiden.__name__)[0].version
    except (pkg_resources.VersionConflict, pkg_resources.DistributionNotFound):
        raise RuntimeError(
            'Cannot detect Raiden version. Did you do python setup.py?  '
            'Refer to https://raiden-network.readthedocs.io/en/latest/'
            'overview_and_guide.html#for-developers',
        )

    system_spec = {
        'raiden': version,
        'python_implementation': platform.python_implementation(),
        'python_version': platform.python_version(),
        'system': system_info,
        'architecture': platform.machine(),
        'distribution': 'bundled' if getattr(sys, 'frozen', False) else 'source',
    }
    return system_spec


def wait_until(func, wait_for=None, sleep_for=0.5):
    """Test for a function and wait for it to return a truth value or to timeout.
    Returns the value or None if a timeout is given and the function didn't return
    inside time timeout
    Args:
        func (callable): a function to be evaluated, use lambda if parameters are required
        wait_for (float, integer, None): the maximum time to wait, or None for an infinite loop
        sleep_for (float, integer): how much to gevent.sleep between calls
    Returns:
        func(): result of func, if truth value, or None"""
    res = func()

    if res:
        return res

    if wait_for:
        deadline = time.time() + wait_for
        while not res and time.time() <= deadline:
            gevent.sleep(sleep_for)
            res = func()

    else:
        while not res:
            gevent.sleep(sleep_for)
            res = func()

    return res


def is_frozen():
    return getattr(sys, 'frozen', False)


def split_in_pairs(arg: Iterable) -> Iterable[Tuple]:
    """ Split given iterable in pairs [a, b, c, d, e] -> [(a, b), (c, d), (e, None)]"""
    # We are using zip_longest with one clever hack:
    # https://docs.python.org/3/library/itertools.html#itertools.zip_longest
    # We create an iterator out of the list and then pass the same iterator to
    # the function two times. Thus the function consumes a different element
    # from the iterator each time and produces the desired result.
    iterator = iter(arg)
    return zip_longest(iterator, iterator)


def create_default_identifier():
    """ Generates a random identifier. """
    return random.randint(0, constants.UINT64_MAX)


def merge_dict(to_update: dict, other_dict: dict):
    """ merges b into a """
    for key, value in other_dict.items():
        has_map = (
            isinstance(value, collections.Mapping) and
            isinstance(to_update.get(key, None), collections.Mapping)
        )

        if has_map:
            merge_dict(to_update[key], value)
        else:
            to_update[key] = value


def optional_address_to_string(
        address: Optional[Union[Address, TokenAddress]] = None,
) -> Optional[str]:
    if address is None:
        return None

    return to_checksum_address(address)


def safe_gas_limit(*estimates: int) -> int:
    """ Calculates a safe gas limit for a number of gas estimates
    including a security margin
    """
    assert None not in estimates, 'if estimateGas returned None it should not reach here'
    calculated_limit = max(estimates)
    return int(calculated_limit * constants.GAS_FACTOR)


def to_rdn(rei: int) -> float:
    """ Convert REI value to RDN. """
    return rei / 10 ** 18


def block_specification_to_number(block: BlockSpecification, web3: Web3) -> BlockNumber:
    """ Converts a block specification to an actual block number """
    if isinstance(block, str):
        msg = f"string block specification can't contain {block}"
        assert block in ('latest', 'pending'), msg
        number = web3.eth.getBlock(block)['number']
    elif isinstance(block, T_BlockHash):
        number = web3.eth.getBlock(block)['number']
    elif isinstance(block, T_BlockNumber):
        number = block
    else:
        if __debug__:
            raise AssertionError(f'Unknown type {type(block)} given for block specification')

    return BlockNumber(number)
