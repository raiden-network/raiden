import pytest
from eth_utils import decode_hex, to_checksum_address

from raiden.constants import EMPTY_HASH, LOCKSROOT_OF_NO_LOCKS
from raiden.tests.utils import factories
from raiden.transfer.secret_registry import events_for_onchain_secretreveal
from raiden.transfer.state import TransactionExecutionStatus
from raiden.transfer.utils import hash_balance_data


@pytest.mark.parametrize(
    "values,expected",
    (
        (
            (0, 0, EMPTY_HASH),
            decode_hex("0x46700b4d40ac5c35af2c22dda2787a91eb567b06c924a8fb8ae9a05b20c08c21"),
        ),
        (
            (1, 5, EMPTY_HASH),
            decode_hex("0xc6b26a4554afa01fb3409b3bd6e7605a1c1af45b7e644282c6ebf34eddb6f893"),
        ),
        ((0, 0, LOCKSROOT_OF_NO_LOCKS), bytes(32)),
    ),
)
def test_hash_balance_data(values, expected):
    assert hash_balance_data(values[0], values[1], values[2]) == expected


def test_events_for_onchain_secretreveal_with_unfit_channels():
    settle = factories.TransactionExecutionStatusProperties()
    settled = factories.create(factories.NettingChannelStateProperties(settle_transaction=settle))
    secret = factories.UNIT_SECRET
    block_hash = factories.make_block_hash()

    events = events_for_onchain_secretreveal(settled, secret, 10, block_hash)
    assert not events, "Secret reveal event should not be generated for settled channel"

    settle = factories.replace(settle, result=TransactionExecutionStatus.FAILURE)
    unusable = factories.create(factories.NettingChannelStateProperties(settle_transaction=settle))

    events = events_for_onchain_secretreveal(unusable, secret, 10, block_hash)
    assert not events, "Secret reveal event should not be generated for unusable channel."


def test_events_for_onchain_secretreveal_typechecks_secret():
    channel = factories.create(factories.NettingChannelStateProperties())
    block_hash = factories.make_block_hash()
    with pytest.raises(ValueError):
        events_for_onchain_secretreveal(channel, "This is an invalid secret", 10, block_hash)


def test_canonical_identifier_validation():
    invalid_chain_id = factories.make_canonical_identifier(chain_identifier="337")
    with pytest.raises(ValueError):
        invalid_chain_id.validate()

    wrong_type_channel_id = factories.make_canonical_identifier(channel_identifier="1")
    with pytest.raises(ValueError):
        wrong_type_channel_id.validate()

    negative_channel_id = factories.make_canonical_identifier(channel_identifier=-5)
    with pytest.raises(ValueError):
        negative_channel_id.validate()

    wrong_format_token_network_address = factories.make_canonical_identifier(
        token_network_address=to_checksum_address(factories.UNIT_TOKEN_NETWORK_ADDRESS)
    )
    with pytest.raises(ValueError):
        wrong_format_token_network_address.validate()
