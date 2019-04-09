import re

from raiden.constants import EthClient
from raiden.utils.typing import Optional, Tuple


def is_supported_client(
        client_version: str,
) -> Tuple[bool, Optional[EthClient]]:
    if client_version.startswith('Parity'):
        matches = re.search(r'//v(\d+)\.(\d+)\.(\d+)', client_version)
        if matches is None:
            return False, None
        major, minor, patch = [
            int(x) for x in matches.groups()
        ]
        if (major, minor, patch) >= (1, 7, 6):
            return True, EthClient.PARITY
    elif client_version.startswith('Geth'):
        matches = re.search(r'/v(\d+)\.(\d+)\.(\d+)', client_version)
        if matches is None:
            return False, None
        major, minor, patch = [
            int(x) for x in matches.groups()
        ]
        if (major, minor, patch) >= (1, 7, 2):
            return True, EthClient.GETH

    return False, None
