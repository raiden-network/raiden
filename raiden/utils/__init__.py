import collections
import os
import random
import re
import sys
import time
from itertools import zip_longest
from typing import Iterable, List, Tuple, Union

import gevent
from coincurve import PrivateKey
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
from raiden_libs.utils.signing import sha3


def random_secret():
    return os.urandom(32)


def ishash(data: bytes) -> bool:
    return isinstance(data, bytes) and len(data) == 32


def is_minified_address(addr):
    return re.compile('(0x)?[a-f0-9]{6,8}').match(addr)


def is_supported_client(
        client_version: str,
) -> typing.Tuple[bool, typing.Optional[constants.EthClient]]:
    if client_version.startswith('Parity'):
        major, minor, patch = [
            int(x) for x in re.search(r'//v(\d+)\.(\d+)\.(\d+)', client_version).groups()
        ]
        if (major, minor, patch) >= (1, 7, 6):
            return True, constants.EthClient.PARITY
    elif client_version.startswith('Geth'):
        major, minor, patch = [
            int(x) for x in re.search(r'/v(\d+)\.(\d+)\.(\d+)', client_version).groups()
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

    addr = decode_hex(addr)
    assert len(addr) in (20, 0)
    return addr


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
    private_key = PrivateKey(private_key_bin)
    return private_key.public_key.format(compressed=False)


def publickey_to_address(publickey: bytes) -> bytes:
    return sha3(publickey[1:])[12:]


def privatekey_to_address(private_key_bin: bytes) -> typing.Address:
    return publickey_to_address(privatekey_to_publickey(private_key_bin))


def privtopub(private_key_bin: bytes) -> bytes:
    """ Returns public key in bitcoins 'bin_electrum' encoding. """
    raw_pubkey = privatekey_to_publickey(private_key_bin)
    assert raw_pubkey.startswith(b'\x04')
    return raw_pubkey[1:]


def get_project_root() -> str:
    return os.path.dirname(raiden.__file__)


def get_relative_path(file_name) -> str:
    prefix = os.path.commonprefix([
        os.path.realpath('.'),
        os.path.realpath(file_name),
    ])
    return file_name.replace(prefix + '/', '')


def get_contract_path(contract_name: str) -> str:
    contract_path = os.path.join(
        get_project_root(),
        'smart_contracts',
        contract_name,
    )
    assert os.path.isfile(contract_path)
    return get_relative_path(contract_path)


def get_system_spec():
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
        system_info = '{} {} {} {}'.format(
            platform.system(),
            '_'.join(platform.architecture()),
            platform.release(),
            platform.machine(),
        )

    try:
        version = pkg_resources.require(raiden.__name__)[0].version
    except (pkg_resources.ContextualVersionConflict, pkg_resources.DistributionNotFound):
        version = None

    system_spec = {
        'raiden': version,
        'python_implementation': platform.python_implementation(),
        'python_version': platform.python_version(),
        'system': system_info,
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


def compare_versions(deployed_version, current_version):
    """Compare version strings of a contract"""
    assert isinstance(deployed_version, str)
    assert isinstance(current_version, str)

    deployed_version = deployed_version.replace('_', '0')
    current_version = current_version.replace('_', '0')

    deployed = [int(x) for x in deployed_version.split('.')]
    current = [int(x) for x in current_version.split('.')]

    if deployed[0] != current[0]:
        return False
    if deployed[1] != current[1]:
        return False
    if deployed[2] != current[2]:
        return False

    return True


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


def optional_address_to_string(address: typing.Address = None) -> typing.Optional[str]:
    if address is None:
        return None

    return to_checksum_address(address)
