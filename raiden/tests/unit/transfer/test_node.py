from raiden.tests.utils.factories import EMPTY_MERKLE_ROOT, HOP1, HOP2, UNIT_SECRETHASH
from raiden.transfer.events import ContractSendChannelBatchUnlock
from raiden.transfer.node import is_transaction_effect_satisfied
from raiden.transfer.state_change import ContractReceiveChannelBatchUnlock


def test_is_transaction_effect_satisfied(
        chain_state,
        token_network_state,
        token_network_id,
        netting_channel_state,
):
    transaction = ContractSendChannelBatchUnlock(
        token_network_identifier=token_network_id,
        channel_identifier=netting_channel_state.identifier,
        merkle_tree_leaves=EMPTY_MERKLE_ROOT,
    )
    state_change = ContractReceiveChannelBatchUnlock(
        transaction_hash=UNIT_SECRETHASH,
        token_network_identifier=token_network_id,
        participant=HOP1,
        partner=HOP2,
        locksroot=EMPTY_MERKLE_ROOT,
        unlocked_amount=0,
        returned_tokens=0,
    )
    # try calling with the address being neither us nor our partner
    assert not is_transaction_effect_satisfied(chain_state, transaction, state_change)

    # now call normally
    state_change.participant = netting_channel_state.our_state.address
    state_change.partner = netting_channel_state.partner_state.address
    assert is_transaction_effect_satisfied(chain_state, transaction, state_change)
