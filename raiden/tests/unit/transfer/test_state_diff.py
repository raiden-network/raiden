import random
from copy import deepcopy

from raiden.tests.utils import factories
from raiden.transfer.state import (
    ChainState,
    NettingChannelEndState,
    NettingChannelState,
    PaymentNetworkState,
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

    payment_network = PaymentNetworkState(b'x', [])
    payment_network_copy = deepcopy(payment_network)
    new.identifiers_to_paymentnetworks['a'] = payment_network
    assert len(diff()) == 0

    token_network = TokenNetworkState(b'a', b'a')
    token_network_copy = deepcopy(token_network)
    payment_network.tokenidentifiers_to_tokennetworks['a'] = token_network
    assert len(diff()) == 0

    channel = NettingChannelState(
        1,
        0,
        b'a',
        1,
        1,
        1,
        2,
        None,
        None,
        TransactionExecutionStatus(result='success'),
    )
    channel_copy = deepcopy(channel)
    token_network.channelidentifiers_to_channels['a'] = channel
    partner_state = NettingChannelEndState(b'a', 0)
    partner_state_copy = deepcopy(partner_state)
    channel.partner_state = partner_state
    assert len(diff()) == 0

    balance_proof = object()
    partner_state.balance_proof = balance_proof
    assert len(diff()) == 1

    old.identifiers_to_paymentnetworks['a'] = payment_network_copy
    assert len(diff()) == 1

    payment_network_copy.tokenidentifiers_to_tokennetworks['a'] = token_network_copy
    assert len(diff()) == 1

    token_network_copy.channelidentifiers_to_channels['a'] = channel_copy
    channel_copy.partner_state = partner_state_copy
    assert len(diff()) == 1

    channel_copy.partner_state.balance_proof = balance_proof
    assert len(diff()) == 0

    channel_copy.partner_state.balance_proof = object()
    assert len(diff()) == 1

    assert diff() == [balance_proof]
