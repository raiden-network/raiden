from binascii import hexlify, unhexlify
import os
import re
import sys
import time
import random
from typing import Tuple, Union, List, Iterable
from itertools import zip_longest

import gevent
from coincurve import PrivateKey
from eth_utils import remove_0x_prefix, keccak, is_checksum_address

import raiden
from raiden import constants
from raiden.exceptions import InvalidAddress
from raiden.utils import typing


def safe_address_decode(address):
    try:
        address = safe_lstrip_hex(address)
        address = unhexlify(address)
    except TypeError:
        pass

    return address


def random_secret():
    return os.urandom(32)


def sha3(data: bytes) -> bytes:
    return keccak(data)


def eth_sign_sha3(data: bytes) -> bytes:
    """
    eth_sign/recover compatible hasher
    Prefixes data with "\x19Ethereum Signed Message:\n<len(data)>"
    """
    if not data.startswith(b'\x19Ethereum Signed Message:'):
        data = b'\x19Ethereum Signed Message:\n%d%s' % (len(data), data)
    return sha3(data)


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
    elif client_version.startswith('EthereumTester'):
        return True, constants.EthClient.TESTER

    return False, None


def address_checksum_and_decode(addr: str) -> typing.Address:
    """ Accepts a string address and turns it into binary.

        Makes sure that the string address provided starts is 0x prefixed and
        checksummed according to EIP55 specification
    """
    if addr[:2] != '0x':
        raise InvalidAddress('Address must be 0x prefixed')

    if not is_checksum_address(addr):
        raise InvalidAddress('Address must be EIP55 checksummed')

    addr = unhexlify(addr[2:])
    assert len(addr) in (20, 0)
    return addr


def data_encoder(data: bytes, length: int = 0) -> str:
    data = hexlify(data)
    return '0x' + data.rjust(length * 2, b'0').decode()


def data_decoder(data: str) -> bytes:
    assert data[:2] == '0x'
    data = data[2:]  # remove 0x
    data = unhexlify(data)
    return data


def quantity_encoder(i: int) -> str:
    """Encode integer quantity `data`."""
    return hex(i).rstrip('L')


def pex(data: bytes) -> str:
    return hexlify(data).decode()[:8]


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


def eth_endpoint_to_hostport(eth_rpc_endpoint: str):
    if eth_rpc_endpoint.startswith('http://'):
        rpc_host = eth_rpc_endpoint[len('http://'):]
        rpc_port = constants.HTTP_PORT
    elif eth_rpc_endpoint.startswith('https://'):
        rpc_host = eth_rpc_endpoint[len('https://'):]
        rpc_port = constants.HTTPS_PORT
    else:
        # Fallback to default port if only an IP address is given
        rpc_host = eth_rpc_endpoint
        rpc_port = constants.ETH_RPC_DEFAULT_PORT

    if ':' in rpc_host:
        return split_endpoint(rpc_host)

    return (rpc_host, rpc_port)


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


def safe_lstrip_hex(val):
    if isinstance(val, str):
        return remove_0x_prefix(val)
    return val


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

    system_spec = dict(
        raiden=pkg_resources.require(raiden.__name__)[0].version,
        python_implementation=platform.python_implementation(),
        python_version=platform.python_version(),
        system=system_info,
        distribution='bundled' if getattr(sys, 'frozen', False) else 'source',
    )
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
    return True


def create_default_identifier():
    """ Generates a random identifier. """
    return random.randint(0, constants.UINT64_MAX)


def merge_dict(a: dict, b: dict, path=None) -> dict:
    """ merges b into a """
    if path is None:
        path = []
    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                merge_dict(a[key], b[key], path + [str(key)])
            elif a[key] == b[key]:
                pass  # same leaf value
            else:
                a[key] = b[key]
        else:
            a[key] = b[key]
    return a
