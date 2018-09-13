from contextlib import contextmanager
from copy import deepcopy

from raiden.transfer import node, views
from raiden.transfer.architecture import StateManager
from raiden.transfer.state import NettingChannelState
from raiden.transfer.utils import hash_balance_data
from raiden.utils import typing


@contextmanager
def temporary_state_manager(state_transition, state):
    state_manager = StateManager(state_transition, state)
    try:
        yield state_manager
    finally:
        state_manager = None


def channel_state_until_balance_hash(
        raiden: 'RaidenService',
        token_address: typing.TokenAddress,
        channel_identifier: typing.ChannelID,
        target_balance_hash: bytes,
) -> typing.Optional[NettingChannelState]:
    """ Go through WAL state changes until a certain balance hash is found. """

    # Restore state from the latest snapshot
    snapshot = raiden.wal.storage.get_latest_state_snapshot()
    if not snapshot:
        # No snapshots were taken before this taking place.
        # Therefore, we return a copy of the current channel state
        channel_state = deepcopy(views.get_channelstate_by_id(
            chain_state=views.state_from_raiden(raiden),
            payment_network_id=raiden.default_registry.address,
            token_address=token_address,
            channel_id=channel_identifier,
        ))
        return channel_state

    last_applied_state_change_id, chain_state = snapshot
    unapplied_state_changes = raiden.wal.storage.get_statechanges_by_identifier(
        from_identifier=last_applied_state_change_id,
        to_identifier='latest',
    )

    # Create a copy WAL
    with temporary_state_manager(node.state_transition, chain_state) as state_manager:
        for state_change in unapplied_state_changes:
            state_manager.dispatch(state_change)
            channel_state = views.get_channelstate_by_id(
                chain_state=chain_state,
                payment_network_id=raiden.default_registry.address,
                token_address=token_address,
                channel_id=channel_identifier,
            )
            if not channel_state:
                continue

            our_latest_balance_proof = channel_state.our_state.balance_proof
            partner_latest_balance_proof = channel_state.partner_state.balance_proof

            balance_hash = None
            if partner_latest_balance_proof:
                balance_hash = hash_balance_data(
                    transferred_amount=partner_latest_balance_proof.transferred_amount,
                    locked_amount=partner_latest_balance_proof.locked_amount,
                    locksroot=partner_latest_balance_proof.locksroot,
                )
            elif our_latest_balance_proof:
                balance_hash = hash_balance_data(
                    transferred_amount=our_latest_balance_proof.transferred_amount,
                    locked_amount=our_latest_balance_proof.locked_amount,
                    locksroot=our_latest_balance_proof.locksroot,
                )

            if target_balance_hash == balance_hash:
                return channel_state

        return None
