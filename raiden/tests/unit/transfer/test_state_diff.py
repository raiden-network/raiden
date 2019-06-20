import random
from copy import deepcopy

from raiden.tests.utils import factories
from raiden.transfer.mediated_transfer.mediation_fee import FeeScheduleState
from raiden.transfer.state import (
    ChainState,
    NettingChannelEndState,
    NettingChannelState,
    PaymentNetworkState,
    TokenNetworkGraphState,
    TokenNetworkState,
    TransactionExecutionStatus,
)
from raiden.transfer.views import detect_balance_proof_change


def test_detect_balance_proof_change():
    prng = random.Random()
    block_hash = factories.make_block_hash()
    old = ChainState(
        pseudo_random_generator=prng,
        block_number=1,
        block_hash=block_hash,
        our_address=2,
        chain_id=3,
    )
    new = ChainState(
        pseudo_random_generator=prng,
        block_number=1,
        block_hash=block_hash,
        our_address=2,
        chain_id=3,
    )

    def diff():
        return list(detect_balance_proof_change(old, new))

    assert len(diff()) == 0

    payment_network = PaymentNetworkState(b"x", [])
    payment_network_copy = deepcopy(payment_network)
    new.identifiers_to_paymentnetworks["a"] = payment_network
    assert len(diff()) == 0

    token_network = TokenNetworkState(
        address=b"a", token_address=b"a", network_graph=TokenNetworkGraphState(b"a")
    )
    token_network_copy = deepcopy(token_network)
    payment_network.tokennetworkaddresses_to_tokennetworks["a"] = token_network
    assert len(diff()) == 0

    channel = NettingChannelState(
        canonical_identifier=factories.make_canonical_identifier(),
        token_address=b"a",
        payment_network_address=1,
        reveal_timeout=1,
        settle_timeout=2,
        our_state=None,
        partner_state=None,
        open_transaction=TransactionExecutionStatus(result="success"),
        settle_transaction=None,
        update_transaction=None,
        close_transaction=None,
        fee_schedule=FeeScheduleState(),
    )
    channel_copy = deepcopy(channel)
    token_network.channelidentifiers_to_channels["a"] = channel
    our_state = NettingChannelEndState(address=b"b", contract_balance=1)
    our_state_copy = deepcopy(our_state)
    partner_state = NettingChannelEndState(address=b"a", contract_balance=0)
    partner_state_copy = deepcopy(partner_state)

    channel.our_state = our_state
    channel.partner_state = partner_state
    assert len(diff()) == 0

    balance_proof = object()
    partner_state.balance_proof = balance_proof
    assert len(diff()) == 1

    old.identifiers_to_paymentnetworks["a"] = payment_network_copy
    assert len(diff()) == 1

    payment_network_copy.tokennetworkaddresses_to_tokennetworks["a"] = token_network_copy
    assert len(diff()) == 1

    token_network_copy.channelidentifiers_to_channels["a"] = channel_copy
    channel_copy.partner_state = partner_state_copy
    assert len(diff()) == 1

    channel_copy.partner_state.balance_proof = balance_proof
    assert len(diff()) == 0

    channel_copy.partner_state.balance_proof = object()
    assert len(diff()) == 1
    assert diff() == [balance_proof]

    # check our_state BP changes
    channel_copy.partner_state.balance_proof = balance_proof
    assert len(diff()) == 0

    channel.our_state.balance_proof = object()
    channel_copy.our_state = our_state_copy
    assert len(diff()) == 1
    assert diff() == [channel.our_state.balance_proof]

    channel_copy.our_state.balance_proof = channel.our_state.balance_proof
    assert len(diff()) == 0
