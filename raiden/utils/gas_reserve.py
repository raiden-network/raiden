from typing import TYPE_CHECKING, Dict, Tuple

from raiden.constants import UNLOCK_TX_GAS_LIMIT
from raiden.network.rpc.client import gas_price_for_fast_transaction
from raiden.transfer import views
from raiden_contracts.contract_manager import gas_measurements

if TYPE_CHECKING:
    from raiden.raiden_service import RaidenService  # pylint: disable=unused-import

GAS_REQUIRED_FOR_CHANNEL_LIFECYCLE_AFTER_SETTLE = UNLOCK_TX_GAS_LIMIT


def gas_required_for_channel_lifecycle_after_close(gas_measurements: Dict[str, int]) -> int:
    return (
        gas_measurements["TokenNetwork.settleChannel"]
        + GAS_REQUIRED_FOR_CHANNEL_LIFECYCLE_AFTER_SETTLE
    )


def gas_required_for_channel_lifecycle_after_open(gas_measurements: Dict[str, int]) -> int:
    return gas_measurements[
        "TokenNetwork.closeChannel"
    ] + gas_required_for_channel_lifecycle_after_close(gas_measurements)


def gas_required_for_channel_lifecycle_complete(gas_measurements: Dict[str, int]) -> int:
    return (
        gas_measurements["TokenNetwork.openChannel"]
        + gas_measurements["TokenNetwork.setTotalDeposit"]
        + gas_required_for_channel_lifecycle_after_open(gas_measurements)
    )


GAS_RESERVE_ESTIMATE_SECURITY_FACTOR = 1.1


def _get_required_gas_estimate(
    gas_measurements: Dict[str, int],
    new_channels: int = 0,
    opening_channels: int = 0,
    opened_channels: int = 0,
    closing_channels: int = 0,
    closed_channels: int = 0,
    settling_channels: int = 0,
    settled_channels: int = 0,
) -> int:
    estimate = 0

    estimate += new_channels * gas_required_for_channel_lifecycle_complete(gas_measurements)
    estimate += opening_channels * gas_required_for_channel_lifecycle_complete(gas_measurements)
    estimate += opened_channels * gas_required_for_channel_lifecycle_after_open(gas_measurements)
    estimate += closing_channels * gas_required_for_channel_lifecycle_after_close(gas_measurements)
    estimate += closed_channels * gas_required_for_channel_lifecycle_after_close(gas_measurements)
    estimate += settling_channels * GAS_REQUIRED_FOR_CHANNEL_LIFECYCLE_AFTER_SETTLE
    estimate += settled_channels * GAS_REQUIRED_FOR_CHANNEL_LIFECYCLE_AFTER_SETTLE

    return estimate


def get_required_gas_estimate(raiden: "RaidenService", channels_to_open: int = 0) -> int:
    num_opening_channels = 0
    num_opened_channels = 0
    num_closing_channels = 0
    num_closed_channels = 0
    num_settling_channels = 0
    num_settled_channels = 0

    # Only use the token networks that have been instantiated. Instantiating
    # the token networks here has a very high performance impact for a registry
    # with lots of tokens.
    #
    # The lock is being acquired to prevent chnages to the dictionary while
    # iterating over it.
    with raiden.proxy_manager.token_network_creation_lock:
        num_opening_channels = sum(
            token_network.opening_channels_count
            for token_network in raiden.proxy_manager.address_to_token_network.values()
        )

    chain_state = views.state_from_raiden(raiden)
    registry_address = raiden.default_registry.address
    token_addresses = views.get_token_identifiers(chain_state, registry_address)

    for token_address in token_addresses:
        num_opened_channels += len(
            views.get_channelstate_open(chain_state, registry_address, token_address)
        )
        num_closing_channels += len(
            views.get_channelstate_closing(chain_state, registry_address, token_address)
        )
        num_closed_channels += len(
            views.get_channelstate_closed(chain_state, registry_address, token_address)
        )
        num_settling_channels += len(
            views.get_channelstate_settling(chain_state, registry_address, token_address)
        )
        num_settled_channels += len(
            views.get_channelstate_settled(chain_state, registry_address, token_address)
        )

    return _get_required_gas_estimate(
        gas_measurements=gas_measurements(raiden.contract_manager.contracts_version),
        opening_channels=num_opening_channels + channels_to_open,
        opened_channels=num_opened_channels,
        closing_channels=num_closing_channels,
        closed_channels=num_closed_channels,
        settling_channels=num_settling_channels,
        settled_channels=num_settled_channels,
    )


def get_reserve_estimate(raiden: "RaidenService", channels_to_open: int = 0) -> int:
    gas_estimate = get_required_gas_estimate(raiden, channels_to_open)
    gas_price = gas_price_for_fast_transaction(raiden.rpc_client.web3)
    reserve_amount = gas_estimate * gas_price

    return round(reserve_amount * GAS_RESERVE_ESTIMATE_SECURITY_FACTOR)


def has_enough_gas_reserve(raiden: "RaidenService", channels_to_open: int = 0) -> Tuple[bool, int]:
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
    current_account_balance = raiden.rpc_client.balance(raiden.rpc_client.address)

    return secure_reserve_estimate <= current_account_balance, secure_reserve_estimate
