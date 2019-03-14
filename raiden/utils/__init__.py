import collections
import os
import random
import re
import sys
import time
from itertools import zip_longest
from typing import Iterable, List, NamedTuple, Optional, Tuple, Union

import gevent
from eth_keys import keys
from eth_utils import (
    add_0x_prefix,
    decode_hex,
    encode_hex,
    is_0x_prefixed,
    is_checksum_address,
    remove_0x_prefix,
    to_checksum_address,
)

import raiden
from raiden import constants
from raiden.exceptions import InvalidAddress
from raiden.utils import typing
from raiden.utils.signing import sha3  # noqa

# Placeholder chain ID for refactoring in scope of #3493
CHAIN_ID_UNSPECIFIED = typing.ChainID(-1)
# Placeholder channel ID for refactoring in scope of #3493
CHANNEL_ID_UNSPECIFIED = typing.ChannelID(-2)


class CanonicalIdentifier(NamedTuple):
    chain_identifier: typing.ChainID
    # introducing the type as Union, to avoid casting for now. Should be only `..Address` later
    token_network_address: Union[typing.TokenNetworkAddress, typing.TokenNetworkID]
    channel_identifier: typing.ChannelID

    def to_dict(self) -> typing.Dict[str, typing.Any]:
        return dict(
            chain_identifier=str(self.chain_identifier),
            token_network_address=encode_hex(self.token_network_address),
            channel_identifier=str(self.channel_identifier),
        )

    @classmethod
    def from_dict(cls, data: typing.Dict[str, typing.Any]) -> 'CanonicalIdentifier':
        return cls(
            chain_identifier=typing.ChainID(int(data['chain_identifier'])),
            token_network_address=typing.TokenNetworkAddress(
                decode_hex(data['token_network_address']),
            ),
            channel_identifier=typing.ChannelID(int(data['channel_identifier'])),
        )


def random_secret():
    """ Return a random 32 byte secret except the 0 secret since it's not accepted in the contracts
    """
    while True:
        secret = os.urandom(32)
        if secret != constants.EMPTY_HASH:
            return secret


def ishash(data: bytes) -> bool:
    return isinstance(data, bytes) and len(data) == 32


def is_minified_address(addr):
    return re.compile('(0x)?[a-f0-9]{6,8}').match(addr)


def is_supported_client(
        client_version: str,
) -> typing.Tuple[bool, typing.Optional[constants.EthClient]]:
    if client_version.startswith('Parity'):
        matches = re.search(r'//v(\d+)\.(\d+)\.(\d+)', client_version)
        if matches is None:
            return False, None
        major, minor, patch = [
            int(x) for x in matches.groups()
        ]
        if (major, minor, patch) >= (1, 7, 6):
            return True, constants.EthClient.PARITY
    elif client_version.startswith('Geth'):
        matches = re.search(r'/v(\d+)\.(\d+)\.(\d+)', client_version)
        if matches is None:
            return False, None
        major, minor, patch = [
            int(x) for x in matches.groups()
        ]
        if (major, minor, patch) >= (1, 7, 2):
            return True, constants.EthClient.GETH

    return False, None


def address_checksum_and_decode(addr: str) -> typing.Address:
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
    return typing.Address(addr_bytes)


def data_encoder(data: bytes, length: int = 0) -> str:
    data = remove_0x_prefix(encode_hex(data))
    return add_0x_prefix(
        data.rjust(length * 2, b'0').decode(),
    )


def data_decoder(data: str) -> bytes:
    assert is_0x_prefixed(data)
    data = decode_hex(data)
    return data


def quantity_encoder(i: int) -> str:
    """Encode integer quantity `data`."""
    return hex(i).rstrip('L')


def pex(data: bytes) -> str:
    return remove_0x_prefix(encode_hex(data))[:8]


def lpex(lst: Iterable[bytes]) -> List[str]:
    return [pex(l) for l in lst]


def host_port_to_endpoint(host: str, port: int) -> str:
    return '{}:{}'.format(host, port)


def split_endpoint(endpoint: str) -> Tuple[str, Union[str, int]]:
    match = re.match(r'(?:[a-z0-9]*:?//)?([^:/]+)(?::(\d+))?', endpoint, re.I)
    if not match:
        raise ValueError('Invalid endpoint', endpoint)
    host, port = match.groups()
    if port:
        port = int(port)
    return host, port


def privatekey_to_publickey(private_key_bin: bytes) -> bytes:
    """ Returns public key in bitcoins 'bin' encoding. """
    if not ishash(private_key_bin):
        raise ValueError('private_key_bin format mismatch. maybe hex encoded?')
    return keys.PrivateKey(private_key_bin).public_key.to_bytes()


def privatekey_to_address(private_key_bin: bytes) -> typing.Address:
    return keys.PrivateKey(private_key_bin).public_key.to_canonical_address()


def get_project_root() -> str:
    return os.path.dirname(raiden.__file__)


def get_relative_path(file_name) -> str:
    prefix = os.path.commonprefix([
        os.path.realpath('.'),
        os.path.realpath(file_name),
    ])
    return file_name.replace(prefix + '/', '')


def get_system_spec() -> typing.Dict[str, str]:
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
    except (pkg_resources.ContextualVersionConflict, pkg_resources.DistributionNotFound):
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
        address: Optional[Union[typing.Address, typing.TokenAddress]] = None,
) -> typing.Optional[str]:
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
