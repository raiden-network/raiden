from raiden.transfer import channel
from raiden.transfer.state import (
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_SETTLED,
    NODE_NETWORK_UNKNOWN,
    NettingChannelState,
    NodeState,
    PaymentMappingState,
    TokenNetworkState,
)
from raiden.utils import typing

# TODO: Either enforce immutability or make a copy of the values returned by
# the view functions


def all_neighbour_nodes(node_state: NodeState) -> typing.Set[typing.Address]:
    """ Return the identifiers for all nodes accross all payment networks which
    have a channel open with this one.
    """
    addresses = set()

    for payment_network in node_state.identifiers_to_paymentnetworks.values():
        for token_network in payment_network.tokenidentifiers_to_tokennetworks.values():
            for channel_state in token_network.partneraddresses_to_channels.values():
                addresses.add(channel_state.partner_state.address)

    return addresses


def block_number(node_state: NodeState) -> int:
    return node_state.block_number


def count_token_network_channels(
        node_state: NodeState,
        payment_network_id: typing.PaymentNetworkID,
        token_address: typing.TokenAddress,
) -> int:
    token_network = get_token_network_by_token_address(
        node_state,
        payment_network_id,
        token_address,
    )

    if token_network is not None:
        count = len(token_network.network_graph.network)
    else:
        count = 0

    return count


def state_from_raiden(raiden) -> NodeState:
    return raiden.wal.state_manager.current_state


def state_from_app(app) -> NodeState:
    return app.raiden.wal.state_manager.current_state


def get_all_messagequeues(node_state: NodeState) -> typing.Dict:
    return node_state.queueids_to_queues


def get_networkstatuses(node_state: NodeState) -> typing.Dict:
    return node_state.nodeaddresses_to_networkstates


def get_node_network_status(
        node_state: NodeState,
        node_address: typing.Address,
) -> str:

    return node_state.nodeaddresses_to_networkstates.get(
        node_address,
        NODE_NETWORK_UNKNOWN,
    )


def get_participants_addresses(
        node_state: NodeState,
        payment_network_id: typing.PaymentNetworkID,
        token_address: typing.TokenAddress,
) -> typing.Set[typing.Address]:
    token_network = get_token_network_by_token_address(
        node_state,
        payment_network_id,
        token_address,
    )

    if token_network is not None:
        addresses = set(token_network.network_graph.network.nodes())
    else:
        addresses = set()

    return addresses


def get_our_capacity_for_token_network(
        node_state: NodeState,
        payment_network_id: typing.PaymentNetworkID,
        token_address: typing.TokenAddress,
) -> int:
    open_channels = get_channelstate_open(
        node_state,
        payment_network_id,
        token_address,
    )

    total_deposit = 0
    for channel_state in open_channels:
        total_deposit += channel_state.our_state.contract_balance

    return total_deposit


def total_deposit_by_token_network(
        node_state: NodeState,
        payment_network_id: typing.PaymentNetworkID,
        token_address: typing.TokenAddress,
) -> int:
    token_network = get_token_network_by_token_address(
        node_state,
        payment_network_id,
        token_address,
    )

    total_deposit = 0
    if token_network:
        for channel_state in token_network.channelidentifiers_to_channels.values():
            total_deposit += channel_state.our_state.contract_balance

    return total_deposit


def get_token_network_identifier_by_token_address(
        node_state: NodeState,
        payment_network_id: typing.Address,
        token_address: typing.Address,
) -> typing.Address:
    token_network = get_token_network_by_token_address(
        node_state,
        payment_network_id,
        token_address,
    )

    token_network_id = getattr(token_network, 'address', None)

    return token_network_id


def get_token_network_addresses_for(
        node_state: NodeState,
        payment_network_id: typing.PaymentNetworkID,
) -> typing.List[typing.Address]:
    """ Return the list of tokens registered with the given payment network. """
    payment_network = node_state.identifiers_to_paymentnetworks.get(payment_network_id)

    if payment_network is not None:
        return [
            token_network.token_address
            for token_network in payment_network.tokenidentifiers_to_tokennetworks.values()
        ]

    return list()


def total_token_network_channels(
        node_state: NodeState,
        payment_network_id: typing.PaymentNetworkID,
        token_address: typing.TokenAddress,
) -> int:

    token_network = get_token_network_by_token_address(
        node_state,
        payment_network_id,
        token_address,
    )

    result = 0
    if token_network:
        result = len(token_network.channelidentifiers_to_channels)

    return result


def get_token_network_by_token_address(
        node_state: NodeState,
        payment_network_id: typing.PaymentNetworkID,
        token_network_id: typing.Address,
) -> typing.Optional[TokenNetworkState]:

    payment_network = node_state.identifiers_to_paymentnetworks.get(payment_network_id)
    if payment_network is not None:
        return payment_network.tokenaddresses_to_tokennetworks.get(token_network_id)

    return None


def get_token_network_by_identifier(
        node_state: NodeState,
        token_network_id: typing.TokenAddress,
) -> typing.Optional[TokenNetworkState]:

    token_network_state = None
    for payment_network_state in node_state.identifiers_to_paymentnetworks.values():
        token_network_state = payment_network_state.tokenidentifiers_to_tokennetworks.get(
            token_network_id,
        )

        if token_network_state:
            return token_network_state

    return token_network_state


def get_channelstate_for(
        node_state: NodeState,
        payment_network_id: typing.PaymentNetworkID,
        token_address: typing.TokenAddress,
        partner_address: typing.Address,
) -> typing.Optional[NettingChannelState]:
    """ Return the NettingChannelState if it exists, None otherwise. """
    token_network = get_token_network_by_token_address(
        node_state,
        payment_network_id,
        token_address,
    )

    channel_state = None
    if token_network:
        channel_state = token_network.partneraddresses_to_channels.get(partner_address)

    return channel_state


def get_channelstate_by_token_network_and_partner(
        node_state: NodeState,
        token_network_id: typing.Address,
        partner_address: typing.Address,
):
    """ Return the NettingChannelState if it exists, None otherwise. """
    token_network = get_token_network_by_identifier(
        node_state,
        token_network_id,
    )

    channel_state = None
    if token_network:
        channel_state = token_network.partneraddresses_to_channels.get(partner_address)

    return channel_state


def get_channelstate_by_token_network_identifier(
        node_state: NodeState,
        token_network_id: typing.Address,
        channel_id: typing.Address,
):
    """ Return the NettingChannelState if it exists, None otherwise. """
    token_network = get_token_network_by_identifier(
        node_state,
        token_network_id,
    )

    channel_state = None
    if token_network:
        channel_state = token_network.channelidentifiers_to_channels.get(channel_id)

    return channel_state


def get_channelstate_by_id(
        node_state: NodeState,
        payment_network_id: typing.PaymentNetworkID,
        token_address: typing.TokenAddress,
        channel_id: typing.Address,
) -> typing.Optional[NettingChannelState]:
    token_network = get_token_network_by_token_address(
        node_state,
        payment_network_id,
        token_address,
    )

    channel_state = None
    if token_network:
        channel_state = token_network.channelidentifiers_to_channels.get(channel_id)

    return channel_state


def get_channestate_for_receiving(
        node_state: NodeState,
        payment_network_id: typing.PaymentNetworkID,
        token_address: typing.TokenAddress,
) -> typing.List[NettingChannelState]:
    """Return the state of channels that had received any transfers in this
    token network.
    """
    token_network = get_token_network_by_token_address(
        node_state,
        payment_network_id,
        token_address,
    )

    result = []
    for channel_state in token_network.channelidentifiers_to_channels.values():
        if channel_state.partner_state.balance_proof:
            result.append(channel_state)

    return result


def get_channelstate_open(
        node_state: NodeState,
        payment_network_id: typing.PaymentNetworkID,
        token_address: typing.TokenAddress,
) -> typing.List[NettingChannelState]:
    """Return the state of open channels in a token network."""
    token_network = get_token_network_by_token_address(
        node_state,
        payment_network_id,
        token_address,
    )

    result = []
    for channel_state in token_network.channelidentifiers_to_channels.values():
        if channel.get_status(channel_state) == CHANNEL_STATE_OPENED:
            result.append(channel_state)

    return result


def get_channelstate_not_settled(
        node_state: NodeState,
        payment_network_id: typing.PaymentNetworkID,
        token_address: typing.TokenAddress,
) -> typing.List[NettingChannelState]:
    """Return the state of open channels in a token network."""
    token_network = get_token_network_by_token_address(
        node_state,
        payment_network_id,
        token_address,
    )

    result = []
    for channel_state in token_network.channelidentifiers_to_channels.values():
        if channel.get_status(channel_state) == CHANNEL_STATE_SETTLED:
            result.append(channel_state)

    return result


def get_channelstate_by_tokenaddress(
        node_state: NodeState,
        payment_network_id: typing.PaymentNetworkID,
        token_address: typing.TokenAddress,
        channel_id: typing.ChannelID,
) -> NettingChannelState:

    token_network = get_token_network_by_token_address(
        node_state,
        payment_network_id,
        token_address,
    )

    channel_state = None
    if token_network:
        channel_state = token_network.channelidentifiers_to_channels.get(channel_id)

    return channel_state


def get_transfer_role(
        node_state: NodeState,
        secrethash: typing.SecretHash,
) -> str:

    transfer_task = node_state.payment_mapping.secrethashes_to_task.get(secrethash)

    result = None
    if isinstance(transfer_task, PaymentMappingState.InitiatorTask):
        result = 'initiator'
    elif isinstance(transfer_task, PaymentMappingState.MediatorTask):
        result = 'mediator'
    elif isinstance(transfer_task, PaymentMappingState.TargetTask):
        result = 'target'

    return result


def list_channelstate_for_tokennetwork(
        node_state: NodeState,
        payment_network_id: typing.PaymentNetworkID,
        token_address: typing.TokenAddress,
) -> typing.List[NettingChannelState]:

    token_network = get_token_network_by_token_address(
        node_state,
        payment_network_id,
        token_address,
    )

    if token_network:
        result = token_network.partneraddresses_to_channels.values()
    else:
        result = []

    return result


def list_channelstate_for_partner(
        node_state: NodeState,
        payment_network_id: typing.PaymentNetworkID,
        partner_address: typing.Address,
) -> typing.List[NettingChannelState]:

    payment_network = node_state.identifiers_to_paymentnetworks.get(payment_network_id)

    result = []
    if payment_network is not None:

        for token_network in payment_network.tokenaddresses_to_tokennetworks.values():
            channel_state = token_network.partneraddresses_to_channels.get(partner_address)
            if channel_state:
                # TODO: Either enforce immutability or make a copy
                result.append(channel_state)

    return result


def list_all_channelstate(node_state: NodeState) -> typing.List[NettingChannelState]:
    result = []
    for payment_network in node_state.identifiers_to_paymentnetworks.values():
        for token_network in payment_network.tokenaddresses_to_tokennetworks.values():
            # TODO: Either enforce immutability or make a copy
            result.extend(
                token_network.partneraddresses_to_channels.values(),
            )

    return result


def search_for_channel(
        node_state: NodeState,
        payment_network_id: typing.PaymentNetworkID,
        channel_id: typing.ChannelID,
) -> NettingChannelState:

    payment_network = node_state.identifiers_to_paymentnetworks.get(payment_network_id)

    result = None
    if payment_network is not None:
        for token_network in payment_network.tokenaddresses_to_tokennetworks.values():
            channel_state = token_network.channelidentifiers_to_channels.get(channel_id)

            if channel_state:
                result = channel_state
                break

    return result


def search_payment_network_by_token_network_id(
        node_state: NodeState,
        token_network_id: typing.Address,
) -> typing.Optional['TokenNetworkState']:

    payment_network_state = None
    for payment_network in node_state.identifiers_to_paymentnetworks.values():
        token_network_state = payment_network.tokenidentifiers_to_tokennetworks.get(
            token_network_id,
        )

        if token_network_state:
            return payment_network_state

    return payment_network_state


def filter_channels_by_partneraddress(
        node_state: NodeState,
        payment_network_id: typing.PaymentNetworkID,
        token_address: typing.TokenAddress,
        partner_addresses: typing.List[typing.Address],
) -> typing.List[NettingChannelState]:

    token_network = get_token_network_by_token_address(
        node_state,
        payment_network_id,
        token_address,
    )

    result = []
    for partner in partner_addresses:
        channel_state = token_network.partneraddresses_to_channels.get(partner)
        if channel_state:
            result.append(channel_state)

    return result
