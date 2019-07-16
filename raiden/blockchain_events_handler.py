from typing import TYPE_CHECKING

import gevent

from raiden.connection_manager import ConnectionManager
from raiden.constants import PATH_FINDING_BROADCASTING_ROOM, RoutingMode
from raiden.messages.path_finding_service import PFSFeeUpdate
from raiden.services import send_pfs_update
from raiden.transfer.architecture import StateChange
from raiden.transfer.state_change import (
    ActionChannelUpdateFee,
    ContractReceiveChannelDeposit,
    ContractReceiveChannelNew,
    ContractReceiveNewTokenNetwork,
    ContractReceiveRouteNew,
)
from raiden.utils.typing import MYPY_ANNOTATION

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.raiden_service import RaidenService  # noqa: F401


def after_new_token_network_create_filter(
    raiden: "RaidenService", state_change: ContractReceiveNewTokenNetwork
) -> None:
    """ Handles the creation of a new token network.

    Add the filter used to synchronize the node with the new TokenNetwork smart
    contract.
    """
    block_number = state_change.block_number
    token_network_address = state_change.token_network.address

    token_network_proxy = raiden.chain.token_network(token_network_address)
    raiden.blockchain_events.add_token_network_listener(
        token_network_proxy=token_network_proxy,
        contract_manager=raiden.contract_manager,
        from_block=block_number,
    )


def after_new_route_join_network(
    raiden: "RaidenService", channelnew: ContractReceiveRouteNew
) -> None:
    """When a new node joins the network it is time to see if we need to open
    new channels.
    """
    connection_manager = raiden.connection_manager_for_token_network(
        channelnew.token_network_address
    )
    retry_connect = gevent.spawn(connection_manager.retry_connect)
    raiden.add_pending_greenlet(retry_connect)


def after_local_fee_update_inform_the_pfs(
    raiden: "RaidenService", update_fee: ActionChannelUpdateFee
) -> None:
    """Update the PFS with the new fee schedule."""
    send_pfs_update(
        raiden=raiden,
        canonical_identifier=update_fee.canonical_identifier,
        update_fee_schedule=True,
    )


def after_new_channel_update_pfs_service(
    raiden: "RaidenService", channelnew: ContractReceiveChannelNew
) -> None:
    """Inform the PFS of the fee schedule once a new channel is opened."""
    if raiden.routing_mode != RoutingMode.PRIVATE:
        fee_update = PFSFeeUpdate.from_channel_state(channelnew.channel_state)
        fee_update.sign(raiden.signer)
        raiden.transport.send_global(PATH_FINDING_BROADCASTING_ROOM, fee_update)


def after_new_channel_start_healthcheck(
    raiden: "RaidenService", channelnew: ContractReceiveChannelNew
) -> None:
    """Start connection healthcheck once a new channel is opened."""
    partner_address = channelnew.channel_state.partner_state.address
    if ConnectionManager.BOOTSTRAP_ADDR != partner_address:
        to_health_check = partner_address
        raiden.start_health_check_for(to_health_check)


def after_new_deposit_join_network(
    raiden: "RaidenService", state_change: ContractReceiveChannelDeposit
) -> None:
    our_address = raiden.address

    if our_address != state_change.deposit_transaction.participant_address:
        return

    # TODO: preserve the old state of the channel
    # previous_balance = previous_channel_state.our_state.contract_balance
    # balance_was_zero = previous_balance == 0
    balance_was_zero = False

    if balance_was_zero:
        connection_manager = raiden.connection_manager_for_token_network(
            state_change.canonical_identifier.token_network_address
        )

        join_channel = gevent.spawn(
            connection_manager.join_channel,
            our_address,
            state_change.deposit_transaction.contract_balance,
        )

        raiden.add_pending_greenlet(join_channel)


def after_blockchain_statechange(raiden: "RaidenService", state_change: StateChange):
    if type(state_change) == ContractReceiveNewTokenNetwork:
        assert isinstance(state_change, ContractReceiveNewTokenNetwork), MYPY_ANNOTATION
        after_new_token_network_create_filter(raiden, state_change)

    elif type(state_change) == ContractReceiveChannelNew:
        assert isinstance(state_change, ContractReceiveChannelNew), MYPY_ANNOTATION
        after_new_channel_update_pfs_service(raiden, state_change)
        after_new_channel_start_healthcheck(raiden, state_change)

    elif type(state_change) == ContractReceiveRouteNew:
        assert isinstance(state_change, ContractReceiveRouteNew), MYPY_ANNOTATION
        after_new_route_join_network(raiden, state_change)

    elif type(state_change) == ContractReceiveChannelDeposit:
        assert isinstance(state_change, ContractReceiveChannelDeposit), MYPY_ANNOTATION
        after_new_deposit_join_network(raiden, state_change)

    elif type(state_change) == ActionChannelUpdateFee:
        assert isinstance(state_change, ActionChannelUpdateFee), MYPY_ANNOTATION
        after_local_fee_update_inform_the_pfs(raiden, state_change)
