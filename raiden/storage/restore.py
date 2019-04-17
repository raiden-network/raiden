from raiden.exceptions import RaidenUnrecoverableError
from raiden.transfer import node, views
from raiden.transfer.state import NettingChannelState
from raiden.utils import CanonicalIdentifier, typing

from .wal import restore_to_state_change


def channel_state_until_state_change(
        raiden,
        payment_network_identifier: typing.PaymentNetworkID,
        token_address: typing.TokenAddress,
        channel_identifier: typing.ChannelID,
        state_change_identifier: int,
) -> typing.Optional[NettingChannelState]:
    """ Go through WAL state changes until a certain balance hash is found. """
    wal = restore_to_state_change(
        transition_function=node.state_transition,
        storage=raiden.wal.storage,
        state_change_identifier=state_change_identifier,
    )

    msg = 'There is a state change, therefore the state must not be None'
    assert wal.state_manager.current_state is not None, msg

    chain_state = wal.state_manager.current_state
    token_network = views.get_token_network_by_token_address(
        chain_state=chain_state,
        payment_network_id=payment_network_identifier,
        token_address=token_address,
    )

    if not token_network:
        return None

    token_network_address = token_network.address

    canonical_identifier = CanonicalIdentifier(
        chain_identifier=chain_state.chain_id,
        token_network_address=token_network_address,
        channel_identifier=channel_identifier,
    )
    channel_state = views.get_channelstate_by_canonical_identifier(
        chain_state=wal.state_manager.current_state,
        canonical_identifier=canonical_identifier,
    )

    if not channel_state:
        raise RaidenUnrecoverableError(
            f"Channel was not found before state_change {state_change_identifier}",
        )

    return channel_state
