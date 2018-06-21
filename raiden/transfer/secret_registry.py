from raiden.transfer.architecture import Event
from raiden.transfer.channel import get_status
from raiden.transfer.events import ContractSendSecretReveal
from raiden.utils import typing
from raiden.transfer.state import (
    CHANNEL_STATES_PRIOR_TO_CLOSED,
    CHANNEL_STATE_CLOSED,
    NettingChannelState,
)


def events_for_onchain_secretreveal(
        channel_state: NettingChannelState,
        block_number: typing.BlockNumber,
        secret: typing.Secret,
) -> typing.List[Event]:
    events = list()

    if not isinstance(secret, typing.T_Secret):
        raise ValueError('secret must be a Secret instance')

    if get_status(channel_state) in CHANNEL_STATES_PRIOR_TO_CLOSED + (CHANNEL_STATE_CLOSED, ):
        reveal_event = ContractSendSecretReveal(secret)
        events.append(reveal_event)

    return events
