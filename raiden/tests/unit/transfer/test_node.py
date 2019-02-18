from raiden.constants import EMPTY_MERKLE_ROOT
from raiden.tests.utils.factories import HOP1, HOP2, UNIT_SECRETHASH, make_block_hash
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
        token_address=token_network_state.token_address,
        token_network_identifier=token_network_id,
        channel_identifier=netting_channel_state.identifier,
        participant=HOP2,
        triggered_by_block_hash=make_block_hash(),
    )
    state_change = ContractReceiveChannelBatchUnlock(
        transaction_hash=UNIT_SECRETHASH,
        token_network_identifier=token_network_id,
        participant=HOP1,
        partner=HOP2,
        locksroot=EMPTY_MERKLE_ROOT,
        unlocked_amount=0,
        returned_tokens=0,
        block_number=1,
        block_hash=make_block_hash(),
    )
    # unlock for a channel in which this node is not a participant must return False
    assert not is_transaction_effect_satisfied(chain_state, transaction, state_change)

    # now call normally with us being the partner and not the participant
    state_change.partner = netting_channel_state.our_state.address
    state_change.participant = netting_channel_state.partner_state.address
    assert not is_transaction_effect_satisfied(chain_state, transaction, state_change)
    # finally call with us being the participant and not the partner which should check out
    state_change.participant = netting_channel_state.our_state.address
    state_change.partner = netting_channel_state.partner_state.address
    assert is_transaction_effect_satisfied(chain_state, transaction, state_change)
