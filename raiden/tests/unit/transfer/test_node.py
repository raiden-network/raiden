from raiden.constants import EMPTY_MERKLE_ROOT
from raiden.tests.utils.factories import HOP1, HOP2, UNIT_SECRETHASH, make_block_hash
from raiden.transfer.events import ContractSendChannelBatchUnlock
from raiden.transfer.node import is_transaction_effect_satisfied, state_transition
from raiden.transfer.state_change import (
    ContractReceiveChannelBatchUnlock,
    ContractReceiveChannelSettled,
)


def test_is_transaction_effect_satisfied(chain_state, token_network_id, netting_channel_state):
    canonical_identifier = netting_channel_state.canonical_identifier
    assert token_network_id == canonical_identifier.token_network_address
    transaction = ContractSendChannelBatchUnlock(
        canonical_identifier=canonical_identifier,
        participant=netting_channel_state.partner_state.address,
        triggered_by_block_hash=make_block_hash(),
    )
    state_change = ContractReceiveChannelBatchUnlock(
        transaction_hash=UNIT_SECRETHASH,
        canonical_identifier=canonical_identifier,
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
    state_change.partner = netting_channel_state.partner_state.address
    state_change.participant = netting_channel_state.our_state.address
    assert not is_transaction_effect_satisfied(chain_state, transaction, state_change)
    # finally call with us being the participant and not the partner which should check out
    state_change.participant = netting_channel_state.partner_state.address
    state_change.partner = netting_channel_state.our_state.address

    # ContractSendChannelBatchUnlock would only be satisfied if both sides are unlocked
    # and if the channel was cleared
    assert not is_transaction_effect_satisfied(chain_state, transaction, state_change)

    channel_settled = ContractReceiveChannelSettled(
        transaction_hash=bytes(32),
        canonical_identifier=canonical_identifier,
        our_onchain_locksroot=EMPTY_MERKLE_ROOT,
        partner_onchain_locksroot=EMPTY_MERKLE_ROOT,
        block_number=1,
        block_hash=make_block_hash(),
    )

    iteration = state_transition(chain_state=chain_state, state_change=channel_settled)

    assert is_transaction_effect_satisfied(iteration.new_state, transaction, state_change)
