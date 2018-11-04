from typing import Tuple

from raiden.constants import UNLOCK_TX_GAS_LIMIT
from raiden.transfer import views
from raiden_contracts.constants import (
    GAS_REQUIRED_FOR_CLOSE_CHANNEL,
    GAS_REQUIRED_FOR_OPEN_CHANNEL,
    GAS_REQUIRED_FOR_SET_TOTAL_DEPOSIT,
    GAS_REQUIRED_FOR_SETTLE_CHANNEL,
)

GAS_REQUIRED_FOR_CHANNEL_LIFECYCLE_AFTER_SETTLE = (
    UNLOCK_TX_GAS_LIMIT
)
GAS_REQUIRED_FOR_CHANNEL_LIFECYCLE_AFTER_CLOSE = (
    GAS_REQUIRED_FOR_SETTLE_CHANNEL + GAS_REQUIRED_FOR_CHANNEL_LIFECYCLE_AFTER_SETTLE
)
GAS_REQUIRED_FOR_CHANNEL_LIFECYCLE_AFTER_OPEN = (
    GAS_REQUIRED_FOR_CLOSE_CHANNEL + GAS_REQUIRED_FOR_CHANNEL_LIFECYCLE_AFTER_CLOSE
)
GAS_REQUIRED_FOR_CHANNEL_LIFECYCLE_COMPLETE = (
    GAS_REQUIRED_FOR_OPEN_CHANNEL +
    GAS_REQUIRED_FOR_SET_TOTAL_DEPOSIT +
    GAS_REQUIRED_FOR_CHANNEL_LIFECYCLE_AFTER_OPEN
)

GAS_RESERVE_ESTIMATE_SECURITY_FACTOR = 1.1


def _get_required_gas_estimate(
    new_channels: int = 0,
    opening_channels: int = 0,
    opened_channels: int = 0,
    closing_channels: int = 0,
    closed_channels: int = 0,
    settling_channels: int = 0,
    settled_channels: int = 0,
) -> int:
    estimate = 0

    estimate += new_channels * GAS_REQUIRED_FOR_CHANNEL_LIFECYCLE_COMPLETE
    estimate += opening_channels * GAS_REQUIRED_FOR_CHANNEL_LIFECYCLE_COMPLETE
    estimate += opened_channels * GAS_REQUIRED_FOR_CHANNEL_LIFECYCLE_AFTER_OPEN
    estimate += closing_channels * GAS_REQUIRED_FOR_CHANNEL_LIFECYCLE_AFTER_CLOSE
    estimate += closed_channels * GAS_REQUIRED_FOR_CHANNEL_LIFECYCLE_AFTER_CLOSE
    estimate += settling_channels * GAS_REQUIRED_FOR_CHANNEL_LIFECYCLE_AFTER_SETTLE
    estimate += settled_channels * GAS_REQUIRED_FOR_CHANNEL_LIFECYCLE_AFTER_SETTLE

    return estimate


def _get_required_gas_estimate_for_state(raiden) -> int:
    chain_state = views.state_from_raiden(raiden)
    registry_address = raiden.default_registry.address
    token_addresses = views.get_token_identifiers(chain_state, registry_address)

    gas_estimate = 0

    for token_address in token_addresses:
        token_network_address = views.get_token_network_identifier_by_token_address(
            chain_state=chain_state,
            payment_network_id=registry_address,
            token_address=token_address,
        )
        num_opening_channels = len(
            raiden.chain.token_network(token_network_address).open_channel_transactions,
        )
        num_opened_channels = len(views.get_channelstate_open(
            chain_state,
            registry_address,
            token_address,
        ))
        num_closing_channels = len(views.get_channelstate_closing(
            chain_state,
            registry_address,
            token_address,
        ))
        num_closed_channels = len(views.get_channelstate_closed(
            chain_state,
            registry_address,
            token_address,
        ))
        num_settling_channels = len(views.get_channelstate_settling(
            chain_state,
            registry_address,
            token_address,
        ))
        num_settled_channels = len(views.get_channelstate_settled(
            chain_state,
            registry_address,
            token_address,
        ))

        gas_estimate += _get_required_gas_estimate(
            opening_channels=num_opening_channels,
            opened_channels=num_opened_channels,
            closing_channels=num_closing_channels,
            closed_channels=num_closed_channels,
            settling_channels=num_settling_channels,
            settled_channels=num_settled_channels,
        )

    return gas_estimate


def get_required_gas_estimate(
        raiden,
        channels_to_open: int = 0,
) -> int:
    gas_estimate = _get_required_gas_estimate_for_state(raiden)
    gas_estimate += _get_required_gas_estimate(new_channels=channels_to_open)
    return gas_estimate


def get_reserve_estimate(
        raiden,
        channels_to_open: int = 0,
) -> int:
    gas_estimate = get_required_gas_estimate(raiden, channels_to_open)
    gas_price = raiden.chain.client.gas_price()
    reserve_amount = gas_estimate * gas_price

    return round(reserve_amount * GAS_RESERVE_ESTIMATE_SECURITY_FACTOR)


def has_enough_gas_reserve(
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
    secure_reserve_estimate = get_reserve_estimate(raiden, channels_to_open)
    current_account_balance = raiden.chain.client.balance(raiden.chain.client.address)

    return secure_reserve_estimate <= current_account_balance, secure_reserve_estimate
