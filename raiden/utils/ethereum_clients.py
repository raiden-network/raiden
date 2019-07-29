import re

from pkg_resources import parse_version

from raiden.constants import (
    HIGHEST_SUPPORTED_GETH_VERSION,
    HIGHEST_SUPPORTED_PARITY_VERSION,
    LOWEST_SUPPORTED_GETH_VERSION,
    LOWEST_SUPPORTED_PARITY_VERSION,
    EthClient,
)
from raiden.utils.typing import Optional, Tuple


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
        our_version = parse_version(matches.groups()[0])
        supported = our_version >= parse_version(
            LOWEST_SUPPORTED_PARITY_VERSION
        ) and our_version <= parse_version(HIGHEST_SUPPORTED_PARITY_VERSION)
        return supported, EthClient.PARITY, str(our_version)
    elif client_version.startswith("Geth"):

        if client_version.startswith("Geth/"):
            # then this is a geth client version from web3.version.node
            matches = re.search(r"/v(\d+\.\d+\.\d+)", client_version)
        else:
            # result of `geth version`
            matches = re.search("Version: (.*)-", client_version)
        if matches is None:
            return False, None, None
        our_version = parse_version(matches.groups()[0])
        supported = our_version >= parse_version(
            LOWEST_SUPPORTED_GETH_VERSION
        ) and our_version <= parse_version(HIGHEST_SUPPORTED_GETH_VERSION)
        return supported, EthClient.GETH, str(our_version)

    return False, None, None
