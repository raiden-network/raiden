import collections
import os
import random
import re
import sys
import time
from itertools import zip_longest
from typing import Any, Callable

import gevent
from eth_keys import keys
from eth_utils import (
    encode_hex,
    is_0x_prefixed,
    is_checksum_address,
    remove_0x_prefix,
    to_canonical_address,
    to_checksum_address,
)
from web3 import Web3

import raiden
from raiden import constants
from raiden.exceptions import InvalidChecksummedAddress
from raiden.utils.signing import sha3  # noqa
from raiden.utils.typing import (
    Address,
    BlockNumber,
    BlockSpecification,
    Dict,
    Endpoint,
    Host,
    HostPort,
    Iterable,
    List,
    Optional,
    PaymentID,
    Port,
    PrivateKey,
    PublicKey,
    Secret,
    T_BlockHash,
    T_BlockNumber,
    TokenAddress,
    Tuple,
    Union,
)


def random_secret() -> Secret:
    """ Return a random 32 byte secret"""
    return Secret(os.urandom(constants.SECRET_LENGTH))


def ishash(data: bytes) -> bool:
    return len(data) == 32


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


def split_endpoint(endpoint: Endpoint) -> HostPort:
    match = re.match(r"(?:[a-z0-9]*:?//)?([^:/]+)(?::(\d+))?", endpoint, re.I)
    if not match:
        raise ValueError("Invalid endpoint", endpoint)
    host, port = match.groups()
    if not port:
        port = "0"
    return Host(host), Port(int(port))


def privatekey_to_publickey(private_key_bin: PrivateKey) -> PublicKey:
    """ Returns public key in bitcoins 'bin' encoding. """
    if not ishash(private_key_bin):
        raise ValueError("private_key_bin format mismatch. maybe hex encoded?")
    return keys.PrivateKey(private_key_bin).public_key.to_bytes()


def privatekey_to_address(private_key_bin: bytes) -> Address:
    return keys.PrivateKey(private_key_bin).public_key.to_canonical_address()


def get_project_root() -> str:
    return os.path.dirname(raiden.__file__)


def get_system_spec() -> Dict[str, Any]:
    """Collect information about the system and installation.
    """
    import pkg_resources
    import platform

    if sys.platform == "darwin":
        system_info = "macOS {} {}".format(platform.mac_ver()[0], platform.architecture()[0])
    else:
        system_info = "{} {} {}".format(
            platform.system(),
            "_".join(part for part in platform.architecture() if part),
            platform.release(),
        )

    try:
        version = pkg_resources.require(raiden.__name__)[0].version
    except (pkg_resources.VersionConflict, pkg_resources.DistributionNotFound):
        raise RuntimeError(
            "Cannot detect Raiden version. Did you do python setup.py?  "
            "Refer to https://raiden-network.readthedocs.io/en/latest/"
            "overview_and_guide.html#for-developers"
        )

    system_spec = {
        "raiden": version,
        "raiden_db_version": constants.RAIDEN_DB_VERSION,
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "system": system_info,
        "architecture": platform.machine(),
        "distribution": "bundled" if getattr(sys, "frozen", False) else "source",
    }
    return system_spec


def wait_until(func: Callable, wait_for: float = None, sleep_for: float = 0.5) -> Any:
    """Test for a function and wait for it to return a truth value or to timeout.
    Returns the value or None if a timeout is given and the function didn't return
    inside time timeout
    Args:
        func: a function to be evaluated, use lambda if parameters are required
        wait_for: the maximum time to wait, or None for an infinite loop
        sleep_for: how much to gevent.sleep between calls
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


def split_in_pairs(arg: Iterable) -> Iterable[Tuple]:
    """ Split given iterable in pairs [a, b, c, d, e] -> [(a, b), (c, d), (e, None)]"""
    # We are using zip_longest with one clever hack:
    # https://docs.python.org/3/library/itertools.html#itertools.zip_longest
    # We create an iterator out of the list and then pass the same iterator to
    # the function two times. Thus the function consumes a different element
    # from the iterator each time and produces the desired result.
    iterator = iter(arg)
    return zip_longest(iterator, iterator)


def create_default_identifier() -> PaymentID:
    """ Generates a random identifier. """
    return PaymentID(random.randint(0, constants.UINT64_MAX))


def merge_dict(to_update: dict, other_dict: dict) -> None:
    """ merges b into a """
    for key, value in other_dict.items():
        has_map = isinstance(value, collections.Mapping) and isinstance(
            to_update.get(key, None), collections.Mapping
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
    assert None not in estimates, "if estimateGas returned None it should not reach here"
    calculated_limit = max(estimates)
    return int(calculated_limit * constants.GAS_FACTOR)


def to_rdn(rei: int) -> float:
    """ Convert REI value to RDN. """
    return rei / 10 ** 18


def block_specification_to_number(block: BlockSpecification, web3: Web3) -> BlockNumber:
    """ Converts a block specification to an actual block number """
    if isinstance(block, str):
        msg = f"string block specification can't contain {block}"
        assert block in ("latest", "pending"), msg
        number = web3.eth.getBlock(block)["number"]
    elif isinstance(block, T_BlockHash):
        number = web3.eth.getBlock(block)["number"]
    elif isinstance(block, T_BlockNumber):
        number = block
    else:
        if __debug__:
            raise AssertionError(f"Unknown type {type(block)} given for block specification")

    return BlockNumber(number)
