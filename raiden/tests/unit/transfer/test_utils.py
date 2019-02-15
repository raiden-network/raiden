import pytest
from eth_utils import decode_hex

from raiden.constants import EMPTY_HASH, EMPTY_MERKLE_ROOT
from raiden.transfer.utils import hash_balance_data


@pytest.mark.parametrize(
    'values,expected',
    (
        ((0, 0, EMPTY_HASH), bytes(32)),
        ((1, 5, EMPTY_MERKLE_ROOT), decode_hex(
            '0xc6b26a4554afa01fb3409b3bd6e7605a1c1af45b7e644282c6ebf34eddb6f893',
        )),
    ),
)
def test_hash_balance_data(values, expected):
    assert(hash_balance_data(values[0], values[1], values[2]) == expected)
