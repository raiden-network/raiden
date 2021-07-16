import re
from enum import Enum
from typing import Union

from packaging.version import LegacyVersion, Version, parse as parse_version

from raiden.constants import (
    HIGHEST_SUPPORTED_GETH_VERSION,
    HIGHEST_SUPPORTED_PARITY_VERSION,
    LOWEST_SUPPORTED_GETH_VERSION,
    LOWEST_SUPPORTED_PARITY_VERSION,
    EthClient,
)
from raiden.utils.typing import Optional, Tuple


class VersionSupport(Enum):
    SUPPORTED = "supported"
    WARN = "warn"
    UNSUPPORTED = "unsupported"


def parse_geth_version(client_version: str) -> Optional[Union[Version, LegacyVersion]]:
    if client_version.startswith("Geth/"):
        # then this is a geth client version from web3.clientVersion
        matches = re.search(r"/v(\d+\.\d+\.\d+)", client_version)
    else:
        # result of `geth version`
        matches = re.search("Version: (.*)-", client_version)
    if matches is None:
        return None
    return parse_version(matches.groups()[0])


def support_check(
    our_version: Union[Version, LegacyVersion],
    highest_supported_version_string: str,
    lowest_supported_version_string: str,
) -> VersionSupport:
    """Check if the eth client version is in the supported range

    If every client strictly adhered to semver, we would only compare major
    version numbers, here. Unfortunately, we had patch-level changes break
    Raiden. So we actually check all version components, now.
    """
    if our_version < parse_version(lowest_supported_version_string):
        return VersionSupport.UNSUPPORTED
    if our_version > parse_version(highest_supported_version_string):
        return VersionSupport.WARN

    return VersionSupport.SUPPORTED


def is_supported_client(
    client_version: str,
) -> Tuple[VersionSupport, Optional[EthClient], Optional[str]]:
    """Takes a client version string either from `web3.clientVersion` or from
    `geth version` or `parity --version` and sees if it is supported.

    Returns a tuple with 3 elements:
    (supported_or_not, none_or_EthClient, none_or_our_version_str)
    """
    if client_version.startswith("Parity") or client_version.startswith("OpenEthereum"):
        # Parity has Parity// at web3.clientVersion and Parity/ prefix at parity --version
        matches = re.search(r"/+v(\d+\.\d+\.\d+)", client_version)
        if matches is None:
            return VersionSupport.UNSUPPORTED, None, None

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
            return VersionSupport.UNSUPPORTED, None, None
        supported = support_check(
            our_version=our_geth_version,
            highest_supported_version_string=HIGHEST_SUPPORTED_GETH_VERSION,
            lowest_supported_version_string=LOWEST_SUPPORTED_GETH_VERSION,
        )
        return supported, EthClient.GETH, str(our_geth_version)

    return VersionSupport.UNSUPPORTED, None, None
