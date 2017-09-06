# -*- coding: utf-8 -*-
import os
import re
import sys
import string
import time
import gevent

from coincurve import PrivateKey
from ethereum.utils import remove_0x_head
from sha3 import keccak_256

import raiden


LETTERS = string.printable


def safe_address_decode(address):
    try:
        address = safe_lstrip_hex(address)
        address = address.decode('hex')
    except TypeError:
        pass

    return address


def sha3(data):
    """
    Raises:
        RuntimeError: If Keccak lib initialization failed, or if the function
        failed to compute the hash.

        TypeError: This function does not accept unicode objects, they must be
        encoded prior to usage.
    """
    return keccak_256(data).digest()


def ishash(data):
    return isinstance(data, (bytes, bytearray)) and len(data) == 32


def isaddress(data):
    return isinstance(data, (bytes, bytearray)) and len(data) == 20


def pex(data):
    return str(data).encode('hex')[:8]


def lpex(lst):
    return [pex(l) for l in lst]


def activate_ultratb():
    from IPython.core import ultratb
    sys.excepthook = ultratb.VerboseTB(call_pdb=True, tb_offset=6)


def host_port_to_endpoint(host, port):
    return '{}:{}'.format(host, port)


def split_endpoint(endpoint):
    match = re.match(r'(?:[a-z0-9]*:?//)?([^:/]+)(?::(\d+))?', endpoint, re.I)
    if not match:
        raise ValueError('Invalid endpoint', endpoint)
    host, port = match.groups()
    if port:
        port = int(port)
    return (host, port)


def publickey_to_address(publickey):
    return sha3(publickey[1:])[12:]


def privatekey_to_address(private_key_bin):
    if not len(private_key_bin) == 32:
        raise ValueError('private_key_bin format mismatch. maybe hex encoded?')
    private_key = PrivateKey(private_key_bin)
    pubkey = private_key.public_key.format(compressed=False)
    return publickey_to_address(pubkey)


def get_project_root():
    return os.path.dirname(raiden.__file__)


def get_contract_path(contract_name):
    contract_path = os.path.join(
        get_project_root(),
        'smart_contracts',
        contract_name
    )
    return os.path.realpath(contract_path)


def safe_lstrip_hex(val):
    if isinstance(val, basestring):
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
    for key, val in storage.iteritems():
        new_key = '0x%064x' % int(key if key != '0x' else '0x0', 16)
        new_val = '0x%064x' % int(val, 16)
        new_storage[new_key] = new_val
    return new_storage


def get_system_spec():
    """Collect informations about the system and installation.
    """
    import pkg_resources
    import raiden
    import platform
    system_spec = dict(
        raiden=pkg_resources.require(raiden.__name__)[0].version,
        python_implementation=platform.python_implementation(),
        python_version=platform.python_version(),
        system='{} {} {}'.format(
            platform.system(),
            '_'.join(platform.architecture()),
            platform.release()
        )
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
