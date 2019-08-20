import re

from pkg_resources import parse_version
from pkg_resources.extern.packaging.version import Version

from raiden.constants import (
    HIGHEST_SUPPORTED_GETH_VERSION,
    HIGHEST_SUPPORTED_PARITY_VERSION,
    LOWEST_SUPPORTED_GETH_VERSION,
    LOWEST_SUPPORTED_PARITY_VERSION,
    EthClient,
)
from raiden.utils.typing import Optional, Tuple


def parse_geth_version(client_version: str) -> Optional[tuple]:
    if client_version.startswith("Geth/"):
        # then this is a geth client version from web3.version.node
        matches = re.search(r"/v(\d+\.\d+\.\d+)", client_version)
    else:
        # result of `geth version`
        matches = re.search("Version: (.*)-", client_version)
    if matches is None:
        return None
    return parse_version(matches.groups()[0])


def support_check(
    our_version: Version,
    highest_supported_version_string: str,
    lowest_supported_version_string: str,
) -> bool:

    # TODO: Is there any better way to get major/minor/patch version from a Version object?
    # Currently we use this private member which is not ideal. release is a tuple.
    # Example: (1, 9, 0)
    our_minor_num = our_version._version.release[1]

    highest_supported_version: Version = parse_version(highest_supported_version_string)
    highest_supported_min_num = highest_supported_version._version.release[1]
    if our_version < parse_version(lowest_supported_version_string):
        return False

    if our_version > highest_supported_version:
        if our_minor_num == highest_supported_min_num:
            return True
        # else
        return False

    return True


def is_supported_client(client_version: str) -> Tuple[bool, Optional[EthClient], Optional[str]]:
    """Takes a client version string either from web3.version.node or from
    `geth version` or `parity --version` and sees if it is supported.

    Returns a tuple with 3 elements:
    (supported_or_not, none_or_EthClient, none_or_our_version_str)
    """
    if client_version.startswith("Parity"):
        # Parity has Parity// at web3.version.node and Parity/ prefix at parity --version
        matches = re.search(r"/+v(\d+\.\d+\.\d+)", client_version)
        if matches is None:
            return False, None, None

        our_parity_version = parse_version(matches.groups()[0])
        supported = support_check(
            our_version=our_parity_version,
            highest_supported_version_string=HIGHEST_SUPPORTED_PARITY_VERSION,
            lowest_supported_version_string=LOWEST_SUPPORTED_PARITY_VERSION,
        )
        return supported, EthClient.PARITY, str(our_parity_version)
    elif client_version.startswith("Geth"):
        our_geth_version = parse_geth_version(client_version)
        if our_geth_version is None:
            return False, None, None
        supported = support_check(
            our_version=our_geth_version,
            highest_supported_version_string=HIGHEST_SUPPORTED_GETH_VERSION,
            lowest_supported_version_string=LOWEST_SUPPORTED_GETH_VERSION,
        )
        return supported, EthClient.GETH, str(our_geth_version)

    return False, None, None
