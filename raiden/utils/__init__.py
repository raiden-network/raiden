# -*- coding: utf-8 -*-
from binascii import hexlify, unhexlify
import os
import re
import string
import sys
import time
from typing import Tuple, Union, List, Iterable

import gevent
from coincurve import PrivateKey
from ethereum.utils import remove_0x_head
from ethereum.abi import ContractTranslator
from ethereum.messages import Log
from sha3 import keccak_256

import raiden
from raiden.utils.typing import address


LETTERS = string.printable


def safe_address_decode(address):
    try:
        address = safe_lstrip_hex(address)
        address = unhexlify(address)
    except TypeError:
        pass

    return address


def sha3(data: bytes) -> bytes:
    """
    Raises:
        RuntimeError: If Keccak lib initialization failed, or if the function
        failed to compute the hash.

        TypeError: This function does not accept unicode objects, they must be
        encoded prior to usage.
    """
    return keccak_256(data).digest()


def ishash(data: bytes) -> bool:
    return isinstance(data, bytes) and len(data) == 32


def isaddress(data: bytes) -> bool:
    return isinstance(data, bytes) and len(data) == 20


def address_decoder(addr: str) -> address:
    if addr[:2] == '0x':
        addr = addr[2:]

    addr = unhexlify(addr)
    assert len(addr) in (20, 0)
    return addr


def address_encoder(address: address) -> str:
    assert len(address) in (20, 0)
    return '0x' + hexlify(address).decode()


def block_tag_encoder(val):
    if isinstance(val, int):
        return hex(val).rstrip('L')

    assert val in ('latest', 'pending')
    return '0x' + hexlify(val).decode()


def data_encoder(data: bytes, length: int = 0) -> str:
    data = hexlify(data)
    return '0x' + data.rjust(length * 2, b'0').decode()


def data_decoder(data: str) -> bytes:
    assert data[:2] == '0x'
    data = data[2:]  # remove 0x
    data = unhexlify(data)
    return data


def quantity_decoder(data: str) -> int:
    assert data[:2] == '0x'
    data = data[2:]  # remove 0x
    return int(data, 16)


def quantity_encoder(i: int) -> str:
    """Encode integer quantity `data`."""
    return hex(i).rstrip('L')


def topic_decoder(topic: str) -> int:
    return int(topic[2:], 16)


def topic_encoder(topic: int) -> str:
    assert isinstance(topic, int)

    if topic == 0:
        return '0x'

    topic = hex(topic).rstrip('L')
    if len(topic) % 2:
        topic = '0x0' + topic[2:]
    return topic


def pex(data: bytes) -> str:
    return hexlify(data).decode()[:8]


def lpex(lst: Iterable[bytes]) -> List[str]:
    return [pex(l) for l in lst]


def activate_ultratb():
    from IPython.core import ultratb
    sys.excepthook = ultratb.VerboseTB(call_pdb=True, tb_offset=6)


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


def privatekey_to_address(private_key_bin: bytes) -> address:
    return publickey_to_address(privatekey_to_publickey(private_key_bin))


def privtopub(private_key_bin: bytes) -> bytes:
    """ Returns public key in bitcoins 'bin_electrum' encoding. """
    raw_pubkey = privatekey_to_publickey(private_key_bin)
    assert raw_pubkey.startswith(b'\x04')
    return raw_pubkey[1:]


def get_project_root() -> str:
    return os.path.dirname(raiden.__file__)


def get_contract_path(contract_name: str) -> str:
    contract_path = os.path.join(
        get_project_root(),
        'smart_contracts',
        contract_name
    )
    return os.path.realpath(contract_path)


def safe_lstrip_hex(val):
    if isinstance(val, str):
        return remove_0x_head(val)
    return val


def get_encoded_transfers(their_transfer, our_transfer):
    """Check for input sanity and return the encoded version of the transfers"""
    if not their_transfer and our_transfer:
        raise ValueError(
            'There is no reason to provide our_transfer when their_transfer'
            ' is not provided'
        )
    their_encoded = their_transfer.encode() if their_transfer else ''
    our_encoded = our_transfer.encode() if our_transfer else ''
    return their_encoded, our_encoded


def camel_to_snake_case(name):
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def snake_to_camel_case(snake_string):
    return snake_string.title().replace('_', '')


def channel_to_api_dict(channel):
    """Takes in a Channel Object and turns it into a dictionary for
    usage in the REST API. Decoding from binary to hex happens through
    the marshmallow AddressField in encoding.py.
    """
    return {
        'channel_address': channel.channel_address,
        'token_address': channel.token_address,
        'partner_address': channel.partner_address,
        'settle_timeout': channel.settle_timeout,
        'reveal_timeout': channel.reveal_timeout,
        'balance': channel.distributable,
        'state': channel.state
    }


def fix_tester_storage(storage):
    """ pyethereum tester doesn't follow the canonical storage encoding:
    Both keys and values of the account storage associative array must be encoded with 64 hex
    digits. Also account_to_dict() from pyethereum can return 0x for a storage
    position. That is an invalid way of representing 0x0.
    Args:
        storage (dict): the storage dictionary from tester
    Returns:
        newstorage (dict): the canonical representation
    """
    new_storage = dict()
    for key, val in storage.items():
        new_key = '0x%064x' % int(key if key != '0x' else '0x0', 16)
        new_val = '0x%064x' % int(val if val != '0x' else '0x0', 16)
        new_storage[new_key] = new_val
    return new_storage


def get_system_spec():
    """Collect information about the system and installation.
    """
    import pkg_resources
    import platform

    if sys.platform == 'darwin':
        system_info = 'macOS {} {}'.format(
            platform.mac_ver()[0],
            platform.architecture()[0]
        )
    else:
        system_info = '{} {} {} {}'.format(
            platform.system(),
            '_'.join(platform.architecture()),
            platform.release(),
            platform.machine()
        )

    system_spec = dict(
        raiden=pkg_resources.require(raiden.__name__)[0].version,
        python_implementation=platform.python_implementation(),
        python_version=platform.python_version(),
        system=system_info
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


def event_decoder(event: Log, contract_translator: ContractTranslator):
    return contract_translator.decode_event(event.topics, event.data)
