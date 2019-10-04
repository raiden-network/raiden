import random
from copy import deepcopy

from raiden.tests.utils.factories import (
    create,
    make_address,
    make_block_hash,
    make_canonical_identifier,
)
from raiden.transfer.architecture import BalanceProofUnsignedState
from raiden.transfer.mediated_transfer.mediation_fee import FeeScheduleState
from raiden.transfer.state import (
    ChainState,
    NettingChannelEndState,
    NettingChannelState,
    TokenNetworkGraphState,
    TokenNetworkRegistryState,
    TokenNetworkState,
    TransactionExecutionStatus,
)
from raiden.transfer.views import detect_balance_proof_change
from raiden.utils.typing import Iterable

MSG_NO_CHANGE = (
    "The channels in old and new states have the same balance proofs, nothing "
    "should be returned."
)
MSG_BALANCE_PROOF_SHOULD_BE_DETECTED = (
    "There is a new balance proof in the new state, it must be returned."
)


def empty(iterator: Iterable) -> bool:
    return len(list(iterator)) == 0


def test_detect_balance_proof_change():
    prng = random.Random()

    block_hash = make_block_hash()
    our_address = make_address()
    empty_chain = ChainState(
        pseudo_random_generator=prng,
        block_number=1,
        block_hash=block_hash,
        our_address=our_address,
        chain_id=3,
    )

    assert empty(detect_balance_proof_change(empty_chain, empty_chain)), MSG_NO_CHANGE
    assert empty(detect_balance_proof_change(empty_chain, deepcopy(empty_chain))), MSG_NO_CHANGE

    token_network_registry_address = make_address()
    chain_with_registry_no_bp = deepcopy(empty_chain)
    chain_with_registry_no_bp.identifiers_to_tokennetworkregistries[
        token_network_registry_address
    ] = TokenNetworkRegistryState(token_network_registry_address, [])

    assert empty(
        detect_balance_proof_change(empty_chain, chain_with_registry_no_bp)
    ), MSG_NO_CHANGE
    assert empty(
        detect_balance_proof_change(chain_with_registry_no_bp, deepcopy(chain_with_registry_no_bp))
    ), MSG_NO_CHANGE

    token_network_address = make_address()
    token_address = make_address()

    chain_with_token_network_no_bp = deepcopy(chain_with_registry_no_bp)
    chain_with_token_network_no_bp.identifiers_to_tokennetworkregistries[
        token_network_registry_address
    ].tokennetworkaddresses_to_tokennetworks[token_network_address] = TokenNetworkState(
        address=token_network_address,
        token_address=token_address,
        network_graph=TokenNetworkGraphState(token_network_address),
    )
    assert empty(
        detect_balance_proof_change(empty_chain, chain_with_token_network_no_bp)
    ), MSG_NO_CHANGE
    assert empty(
        detect_balance_proof_change(chain_with_registry_no_bp, chain_with_token_network_no_bp)
    ), MSG_NO_CHANGE
    assert empty(
        detect_balance_proof_change(
            chain_with_token_network_no_bp, deepcopy(chain_with_token_network_no_bp)
        )
    ), MSG_NO_CHANGE

    partner_address = make_address()
    canonical_identifier = make_canonical_identifier()
    channel_no_bp = NettingChannelState(
        canonical_identifier=canonical_identifier,
        token_address=token_address,
        token_network_registry_address=token_network_registry_address,
        reveal_timeout=1,
        settle_timeout=2,
        our_state=NettingChannelEndState(address=our_address, contract_balance=1),
        partner_state=NettingChannelEndState(address=partner_address, contract_balance=0),
        open_transaction=TransactionExecutionStatus(result="success"),
        settle_transaction=None,
        update_transaction=None,
        close_transaction=None,
        fee_schedule=FeeScheduleState(),
    )

    chain_with_channel_no_bp = deepcopy(chain_with_token_network_no_bp)
    chain_with_token_network_no_bp.identifiers_to_tokennetworkregistries[
        token_network_registry_address
    ].tokennetworkaddresses_to_tokennetworks[token_network_address].channelidentifiers_to_channels[
        canonical_identifier.channel_identifier
    ] = channel_no_bp

    assert empty(detect_balance_proof_change(empty_chain, chain_with_channel_no_bp)), MSG_NO_CHANGE
    assert empty(
        detect_balance_proof_change(chain_with_registry_no_bp, chain_with_channel_no_bp)
    ), MSG_NO_CHANGE
    assert empty(
        detect_balance_proof_change(chain_with_token_network_no_bp, chain_with_channel_no_bp)
    ), MSG_NO_CHANGE
    assert empty(
        detect_balance_proof_change(chain_with_channel_no_bp, deepcopy(chain_with_channel_no_bp))
    ), MSG_NO_CHANGE

    channel_with_sent_bp = deepcopy(channel_no_bp)
    channel_with_sent_bp.our_state.balance_proof = create(BalanceProofUnsignedState)

    chain_with_sent_bp = deepcopy(chain_with_token_network_no_bp)
    chain_with_sent_bp.identifiers_to_tokennetworkregistries[
        token_network_registry_address
    ].tokennetworkaddresses_to_tokennetworks[token_network_address].channelidentifiers_to_channels[
        canonical_identifier.channel_identifier
    ] = channel_with_sent_bp

    assert not empty(
        detect_balance_proof_change(empty_chain, chain_with_sent_bp)
    ), MSG_BALANCE_PROOF_SHOULD_BE_DETECTED
    assert not empty(
        detect_balance_proof_change(chain_with_registry_no_bp, chain_with_sent_bp)
    ), MSG_BALANCE_PROOF_SHOULD_BE_DETECTED
    assert not empty(
        detect_balance_proof_change(chain_with_token_network_no_bp, chain_with_sent_bp)
    ), MSG_BALANCE_PROOF_SHOULD_BE_DETECTED
    assert not empty(
        detect_balance_proof_change(chain_with_channel_no_bp, chain_with_sent_bp)
    ), MSG_BALANCE_PROOF_SHOULD_BE_DETECTED
    assert empty(
        detect_balance_proof_change(chain_with_sent_bp, deepcopy(chain_with_sent_bp))
    ), MSG_NO_CHANGE

    channel_with_received_bp = deepcopy(channel_no_bp)
    channel_with_received_bp.partner_state.balance_proof = create(BalanceProofUnsignedState)

    chain_with_received_bp = deepcopy(chain_with_token_network_no_bp)
    chain_with_received_bp.identifiers_to_tokennetworkregistries[
        token_network_registry_address
    ].tokennetworkaddresses_to_tokennetworks[token_network_address].channelidentifiers_to_channels[
        canonical_identifier.channel_identifier
    ] = channel_with_sent_bp

    # asserting with `channel_with_received_bp` and `channel_with_sent_bp`
    # doesn't make sense, because one of the balance proofs would have to
    # disappear (which is a bug)
    assert not empty(
        detect_balance_proof_change(empty_chain, chain_with_received_bp)
    ), MSG_BALANCE_PROOF_SHOULD_BE_DETECTED
    assert not empty(
        detect_balance_proof_change(chain_with_registry_no_bp, chain_with_received_bp)
    ), MSG_BALANCE_PROOF_SHOULD_BE_DETECTED
    assert not empty(
        detect_balance_proof_change(chain_with_token_network_no_bp, chain_with_received_bp)
    ), MSG_BALANCE_PROOF_SHOULD_BE_DETECTED
    assert not empty(
        detect_balance_proof_change(chain_with_channel_no_bp, chain_with_received_bp)
    ), MSG_BALANCE_PROOF_SHOULD_BE_DETECTED
    assert empty(
        detect_balance_proof_change(chain_with_received_bp, deepcopy(chain_with_received_bp))
    ), MSG_NO_CHANGE

    chain_with_sent_and_received_bp = deepcopy(chain_with_token_network_no_bp)
    ta_to_tn = chain_with_sent_and_received_bp.identifiers_to_tokennetworkregistries
    channel_with_sent_and_recived_bp = (
        ta_to_tn[token_network_registry_address]
        .tokennetworkaddresses_to_tokennetworks[token_network_address]
        .channelidentifiers_to_channels[canonical_identifier.channel_identifier]
    )
    channel_with_sent_and_recived_bp.partner_state.balance_proof = deepcopy(
        channel_with_received_bp.partner_state.balance_proof
    )
    channel_with_sent_and_recived_bp.our_state.balance_proof = deepcopy(
        channel_with_received_bp.our_state.balance_proof
    )

    assert not empty(
        detect_balance_proof_change(empty_chain, chain_with_sent_and_received_bp)
    ), MSG_BALANCE_PROOF_SHOULD_BE_DETECTED
    assert not empty(
        detect_balance_proof_change(chain_with_registry_no_bp, chain_with_sent_and_received_bp)
    ), MSG_BALANCE_PROOF_SHOULD_BE_DETECTED
    assert not empty(
        detect_balance_proof_change(
            chain_with_token_network_no_bp, chain_with_sent_and_received_bp
        )
    ), MSG_BALANCE_PROOF_SHOULD_BE_DETECTED
    assert not empty(
        detect_balance_proof_change(chain_with_channel_no_bp, chain_with_sent_and_received_bp)
    ), MSG_BALANCE_PROOF_SHOULD_BE_DETECTED
    assert not empty(
        detect_balance_proof_change(chain_with_received_bp, chain_with_sent_and_received_bp)
    ), MSG_BALANCE_PROOF_SHOULD_BE_DETECTED
    assert not empty(
        detect_balance_proof_change(chain_with_sent_bp, chain_with_sent_and_received_bp)
    ), MSG_BALANCE_PROOF_SHOULD_BE_DETECTED
    assert empty(
        detect_balance_proof_change(
            chain_with_sent_and_received_bp, deepcopy(chain_with_sent_and_received_bp)
        )
    ), MSG_NO_CHANGE
