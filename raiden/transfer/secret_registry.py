from raiden.transfer.channel import get_status
from raiden.transfer.events import ContractSendSecretReveal
from raiden.transfer.state import (
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATES_PRIOR_TO_CLOSED,
    NettingChannelState,
)
from raiden.utils import typing


def events_for_onchain_secretreveal(
        channel_state: NettingChannelState,
        secret: typing.Secret,
        expiration: typing.BlockExpiration,
) -> typing.List[ContractSendSecretReveal]:
    events = list()

    if not isinstance(secret, typing.T_Secret):
        raise ValueError('secret must be a Secret instance')

    if get_status(channel_state) in CHANNEL_STATES_PRIOR_TO_CLOSED + (CHANNEL_STATE_CLOSED, ):
        reveal_event = ContractSendSecretReveal(
            expiration=expiration,
            secret=secret,
        )
        events.append(reveal_event)

    return events
