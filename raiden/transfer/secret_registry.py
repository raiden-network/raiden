from raiden.transfer.architecture import Event
from raiden.transfer.channel import get_status
from raiden.transfer.events import ContractSendSecretReveal
from raiden.transfer.state import (
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATES_PRIOR_TO_CLOSED,
    NettingChannelState,
)
from raiden.utils.typing import BlockExpiration, BlockHash, List, Secret, T_Secret


def events_for_onchain_secretreveal(
        channel_state: NettingChannelState,
        secret: Secret,
        expiration: BlockExpiration,
        block_hash: BlockHash,
) -> List[Event]:
    events: List[Event] = list()

    if not isinstance(secret, T_Secret):
        raise ValueError('secret must be a Secret instance')

    if get_status(channel_state) in CHANNEL_STATES_PRIOR_TO_CLOSED + (CHANNEL_STATE_CLOSED, ):
        reveal_event = ContractSendSecretReveal(
            expiration=expiration,
            secret=secret,
            triggered_by_block_hash=block_hash,
        )
        events.append(reveal_event)

    return events
