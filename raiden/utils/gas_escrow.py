from typing import Tuple

from raiden.constants import (
    GAS_USED_OPEN_CHANNEL,
    GAS_USED_SET_TOTAL_DEPOSIT,
    GAS_USED_CLOSE_CHANNEL,
    GAS_USED_SETTLE_CHANNEL,
    GAS_USED_UNLOCK_1_LOCKS,
)
from raiden.transfer import views

CHANNEL_LIFECYCLE_SETTLE_GAS_USED = GAS_USED_SETTLE_CHANNEL + GAS_USED_UNLOCK_1_LOCKS
CHANNEL_LIFECYCLE_CLOSE_GAS_USED = (
    GAS_USED_CLOSE_CHANNEL + CHANNEL_LIFECYCLE_SETTLE_GAS_USED
)
CHANNEL_LIFECYCLE_NO_DEPOSIT_GAS_USED = (
    CHANNEL_LIFECYCLE_CLOSE_GAS_USED + GAS_USED_OPEN_CHANNEL
)
CHANNEL_LIFECYCLE_GAS_USED = CHANNEL_LIFECYCLE_NO_DEPOSIT_GAS_USED + GAS_USED_SET_TOTAL_DEPOSIT

GAS_PRICE_SECURITY_FACTOR = 1.1


def _get_gas_estimate(
    new_channels: int = 0,
    opened_channels: int = 0,
    closed_channels: int = 0,
    settled_channels: int = 0,
) -> int:
    estimate = 0

    estimate += new_channels * CHANNEL_LIFECYCLE_GAS_USED
    estimate += opened_channels * CHANNEL_LIFECYCLE_CLOSE_GAS_USED
    estimate += closed_channels * CHANNEL_LIFECYCLE_SETTLE_GAS_USED
    estimate += settled_channels * GAS_USED_UNLOCK_1_LOCKS

    return estimate


def _get_gas_estimate_for_state(raiden) -> int:
    chain_state = views.state_from_raiden(raiden)
    token_addresses = views.get_token_identifiers(chain_state, raiden.default_registry.address)

    gas_estimate = 0

    for token_address in token_addresses:
        num_opened_channels = len(views.get_channelstate_open(
            chain_state,
            raiden.default_registry.address,
            token_address,
        ))
        num_closed_channels = len(views.get_channelstate_closed(
            chain_state,
            raiden.default_registry.address,
            token_address,
        ))

        gas_estimate += _get_gas_estimate(
            opened_channels=num_opened_channels,
            closed_channels=num_closed_channels,
        )

    return gas_estimate


def has_enough_gas_escrow(
    raiden,
    channels_to_open: int = 0,
) -> Tuple[bool, int]:
    """ Checks if the account has enough balance to handle the lifecycles of all
    open channels as well as the to be created channels.

    Note: This is just an estimation.

    Args:
        raiden: A raiden service instance
        channels_to_open: The number of new channels that should be opened

    Returns:
        Tuple of a boolean denoting if the account has enough balance for
        the remaining lifecycle events and the estimate for the remaining
        lifecycle cost
    """
    gas_estimate = _get_gas_estimate_for_state(raiden)
    gas_estimate += _get_gas_estimate(new_channels=channels_to_open)

    gas_price = raiden.chain.client.gasprice()
    escrow_amount = gas_estimate * gas_price

    secure_escrow_estimate = round(escrow_amount * GAS_PRICE_SECURITY_FACTOR)
    current_account_balance = raiden.chain.client.balance(raiden.chain.client.sender)

    return secure_escrow_estimate <= current_account_balance, secure_escrow_estimate
