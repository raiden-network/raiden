from raiden.tests.utils.factories import (
    EMPTY_MERKLE_ROOT,
    HOP1,
    HOP2,
    UNIT_CHANNEL_ID,
    UNIT_SECRETHASH,
    UNIT_TOKEN_NETWORK_ADDRESS,
)
from raiden.transfer.events import ContractSendChannelBatchUnlock
from raiden.transfer.node import is_transaction_effect_satisfied
from raiden.transfer.state_change import ContractReceiveChannelBatchUnlock


def test_is_transaction_effect_satisfied(chain_state):
    transaction = ContractSendChannelBatchUnlock(
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
        channel_identifier=UNIT_CHANNEL_ID,
        merkle_tree_leaves=EMPTY_MERKLE_ROOT,
    )
    state_change = ContractReceiveChannelBatchUnlock(
        transaction_hash=UNIT_SECRETHASH,
        token_network_identifier=UNIT_TOKEN_NETWORK_ADDRESS,
        participant=HOP1,
        partner=HOP2,
        locksroot=EMPTY_MERKLE_ROOT,
        unlocked_amount=0,
        returned_tokens=0,
    )
    assert is_transaction_effect_satisfied(chain_state, transaction, state_change)
