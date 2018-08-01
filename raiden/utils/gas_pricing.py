from raiden.constants import (
    GAS_USED_OPEN_CHANNEL,
    GAS_USED_SET_TOTAL_DEPOSIT,
    GAS_USED_CLOSE_CHANNEL,
    GAS_USED_SETTLE_CHANNEL,
    GAS_USED_UNLOCK_1_LOCKS,
)
from raiden.transfer import views
from raiden.utils import typing

CHANNEL_LIFECYCLE_SETTLE_GAS_USED = GAS_USED_SETTLE_CHANNEL + GAS_USED_UNLOCK_1_LOCKS
CHANNEL_LIFECYCLE_END_GAS_USED = (
    GAS_USED_CLOSE_CHANNEL + CHANNEL_LIFECYCLE_SETTLE_GAS_USED
)
CHANNEL_LIFECYCLE_NO_DEPOSIT_GAS_USED = (
    CHANNEL_LIFECYCLE_END_GAS_USED + GAS_USED_OPEN_CHANNEL
)
CHANNEL_LIFECYCLE_GAS_USED = CHANNEL_LIFECYCLE_NO_DEPOSIT_GAS_USED + GAS_USED_SET_TOTAL_DEPOSIT

GAS_PRICE_SECURITY_FACTOR = 1.1


def get_required_balance(raiden) -> typing.Balance:
    """ Estimates the necessary balance to settle all channels.

    Args:
        raiden: A raiden service instance

    Returns:
        Estimate of the necessary balance to finish all channel lifecycles
    """
    chain_state = views.state_from_raiden(raiden)
    token_addresses = views.get_token_identifiers(chain_state, raiden.default_registry.address)

    gas_estimate = 0

    for token_address in token_addresses:
        num_open_channels = len(views.get_channelstate_open(
            chain_state,
            raiden.default_registry.address,
            token_address,
        ))
        gas_estimate += num_open_channels * CHANNEL_LIFECYCLE_END_GAS_USED

        num_closed_channels = len(views.get_channelstate_closed(
            chain_state,
            raiden.default_registry.address,
            token_address,
        ))
        gas_estimate += num_closed_channels * CHANNEL_LIFECYCLE_SETTLE_GAS_USED

    gas_price = raiden.chain.client.gasprice()
    escrow_amount = gas_estimate * gas_price

    secure_escrow_estimate = round(escrow_amount * GAS_PRICE_SECURITY_FACTOR)
    return secure_escrow_estimate
