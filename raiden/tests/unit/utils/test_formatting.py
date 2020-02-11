import os

from eth_utils import to_checksum_address as eth_utils_checksum

from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import Address


def test_random_addresses():
    for _ in range(100):
        address_bytes = Address(os.urandom(20))
        assert eth_utils_checksum(address_bytes) == to_checksum_address(address_bytes)
