from raiden.exceptions import RaidenUnrecoverableError
from raiden.storage.wal import restore_to_state_change
from raiden.transfer import node, views
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.state import NettingChannelState
from raiden.utils import typing


def channel_state_until_state_change(
    raiden, canonical_identifier: CanonicalIdentifier, state_change_identifier: int
) -> typing.Optional[NettingChannelState]:
    """ Go through WAL state changes until a certain balance hash is found. """
    wal = restore_to_state_change(
        transition_function=node.state_transition,
        storage=raiden.wal.storage,
        state_change_identifier=state_change_identifier,
    )

    msg = "There is a state change, therefore the state must not be None"
    assert wal.state_manager.current_state is not None, msg

    chain_state = wal.state_manager.current_state
    channel_state = views.get_channelstate_by_canonical_identifier(
        chain_state=chain_state, canonical_identifier=canonical_identifier
    )

    if not channel_state:
        raise RaidenUnrecoverableError(
            f"Channel was not found before state_change {state_change_identifier}"
        )

    return channel_state
