from raiden.transfer import channel
from raiden.transfer.architecture import ContractSendEvent, State
from raiden.transfer.state import (
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_CLOSING,
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_SETTLED,
    CHANNEL_STATE_SETTLING,
    CHANNEL_STATE_UNUSABLE,
    NODE_NETWORK_UNKNOWN,
    BalanceProofSignedState,
    ChainState,
    InitiatorTask,
    MediatorTask,
    NettingChannelState,
    PaymentNetworkState,
    QueueIdsToQueues,
    TargetTask,
    TokenNetworkState,
    TransferTask,
)
from raiden.utils.typing import (
    Address,
    BlockNumber,
    Callable,
    ChannelID,
    Dict,
    Iterator,
    List,
    Optional,
    PaymentNetworkID,
    SecretHash,
    Set,
    TokenAddress,
    TokenNetworkID,
)

# TODO: Either enforce immutability or make a copy of the values returned by
# the view functions


def all_neighbour_nodes(chain_state: ChainState) -> Set[Address]:
    """ Return the identifiers for all nodes accross all payment networks which
    have a channel open with this one.
    """
    addresses = set()

    for payment_network in chain_state.identifiers_to_paymentnetworks.values():
        for token_network in payment_network.tokenidentifiers_to_tokennetworks.values():
            channel_states = token_network.channelidentifiers_to_channels.values()
            for channel_state in channel_states:
                addresses.add(channel_state.partner_state.address)

    return addresses


def block_number(chain_state: ChainState) -> BlockNumber:
    return chain_state.block_number


def count_token_network_channels(
        chain_state: ChainState,
        payment_network_id: PaymentNetworkID,
        token_address: TokenAddress,
) -> int:
    token_network = get_token_network_by_token_address(
        chain_state,
        payment_network_id,
        token_address,
    )

    if token_network is not None:
        count = len(token_network.network_graph.network)
    else:
        count = 0

    return count


def state_from_raiden(raiden) -> ChainState:
    return raiden.wal.state_manager.current_state


def state_from_app(app) -> ChainState:
    return app.raiden.wal.state_manager.current_state


def get_pending_transactions(chain_state: ChainState) -> List[ContractSendEvent]:
    return chain_state.pending_transactions


def get_all_messagequeues(
        chain_state: ChainState,
) -> QueueIdsToQueues:
    return chain_state.queueids_to_queues


def get_networkstatuses(chain_state: ChainState) -> Dict:
    return chain_state.nodeaddresses_to_networkstates


def get_node_network_status(
        chain_state: ChainState,
        node_address: Address,
) -> str:

    return chain_state.nodeaddresses_to_networkstates.get(
        node_address,
        NODE_NETWORK_UNKNOWN,
    )


def get_participants_addresses(
        chain_state: ChainState,
        payment_network_id: PaymentNetworkID,
        token_address: TokenAddress,
) -> Set[Address]:
    token_network = get_token_network_by_token_address(
        chain_state,
        payment_network_id,
        token_address,
    )

    if token_network is not None:
        addresses = set(token_network.network_graph.network.nodes())
    else:
        addresses = set()

    return addresses


def get_our_capacity_for_token_network(
        chain_state: ChainState,
        payment_network_id: PaymentNetworkID,
        token_address: TokenAddress,
) -> int:
    open_channels = get_channelstate_open(
        chain_state,
        payment_network_id,
        token_address,
    )

    total_deposit = 0
    for channel_state in open_channels:
        total_deposit += channel_state.our_state.contract_balance

    return total_deposit


def get_payment_network_identifiers(
        chain_state: ChainState,
) -> List[PaymentNetworkID]:
    return list(chain_state.identifiers_to_paymentnetworks.keys())


def get_token_network_registry_by_token_network_identifier(
        chain_state: ChainState,
        token_network_identifier: Address,
) -> Optional[PaymentNetworkState]:
    for payment_network in chain_state.identifiers_to_paymentnetworks.values():
        if token_network_identifier in payment_network.tokenidentifiers_to_tokennetworks:
            return payment_network

    return None


def get_token_network_identifier_by_token_address(
        chain_state: ChainState,
        payment_network_id: PaymentNetworkID,
        token_address: TokenAddress,
) -> Optional[TokenNetworkID]:
    token_network = get_token_network_by_token_address(
        chain_state,
        payment_network_id,
        token_address,
    )

    token_network_id = getattr(token_network, 'address', None)

    return token_network_id


def get_token_network_identifiers(
        chain_state: ChainState,
        payment_network_id: PaymentNetworkID,
) -> List[TokenNetworkID]:
    """ Return the list of token networks registered with the given payment network. """
    payment_network = chain_state.identifiers_to_paymentnetworks.get(payment_network_id)

    if payment_network is not None:
        return [
            token_network.address
            for token_network in payment_network.tokenidentifiers_to_tokennetworks.values()
        ]

    return list()


def get_token_identifiers(
        chain_state: ChainState,
        payment_network_id: PaymentNetworkID,
) -> List[TokenAddress]:
    """ Return the list of tokens registered with the given payment network. """
    payment_network = chain_state.identifiers_to_paymentnetworks.get(payment_network_id)

    if payment_network is not None:
        return [
            token_address
            for token_address in payment_network.tokenaddresses_to_tokenidentifiers.keys()
        ]

    return list()


def total_token_network_channels(
        chain_state: ChainState,
        payment_network_id: PaymentNetworkID,
        token_address: TokenAddress,
) -> int:

    token_network = get_token_network_by_token_address(
        chain_state,
        payment_network_id,
        token_address,
    )

    result = 0
    if token_network:
        result = len(token_network.channelidentifiers_to_channels)

    return result


def get_token_network_by_token_address(
        chain_state: ChainState,
        payment_network_id: PaymentNetworkID,
        token_address: TokenAddress,
) -> Optional[TokenNetworkState]:

    payment_network = chain_state.identifiers_to_paymentnetworks.get(payment_network_id)
    token_network_id = None

    if payment_network is not None:
        token_network_id = payment_network.tokenaddresses_to_tokenidentifiers.get(token_address)

    if token_network_id:
        return payment_network.tokenidentifiers_to_tokennetworks.get(token_network_id)

    return None


def get_token_network_by_identifier(
        chain_state: ChainState,
        token_network_id: TokenNetworkID,
) -> Optional[TokenNetworkState]:

    token_network_state = None
    for payment_network_state in chain_state.identifiers_to_paymentnetworks.values():
        token_network_state = payment_network_state.tokenidentifiers_to_tokennetworks.get(
            token_network_id,
        )
        if token_network_state:
            return token_network_state

    return token_network_state


def get_channelstate_for(
        chain_state: ChainState,
        payment_network_id: PaymentNetworkID,
        token_address: TokenAddress,
        partner_address: Address,
) -> Optional[NettingChannelState]:
    """ Return the NettingChannelState if it exists, None otherwise. """
    token_network = get_token_network_by_token_address(
        chain_state,
        payment_network_id,
        token_address,
    )

    channel_state = None
    if token_network:
        channels = [
            token_network.channelidentifiers_to_channels[channel_id]
            for channel_id in token_network.partneraddresses_to_channelidentifiers[partner_address]
        ]
        states = filter_channels_by_status(
            channels,
            [CHANNEL_STATE_UNUSABLE],
        )
        # If multiple channel states are found, return the last one.
        if states:
            channel_state = states[-1]

    return channel_state


def get_channelstate_by_token_network_and_partner(
        chain_state: ChainState,
        token_network_id: TokenNetworkID,
        partner_address: Address,
) -> Optional[NettingChannelState]:
    """ Return the NettingChannelState if it exists, None otherwise. """
    token_network = get_token_network_by_identifier(
        chain_state,
        token_network_id,
    )

    channel_state = None
    if token_network:
        channels = [
            token_network.channelidentifiers_to_channels[channel_id]
            for channel_id in token_network.partneraddresses_to_channelidentifiers[partner_address]
        ]
        states = filter_channels_by_status(
            channels,
            [CHANNEL_STATE_UNUSABLE],
        )
        if states:
            channel_state = states[-1]

    return channel_state


def get_channelstate_by_token_network_identifier(
        chain_state: ChainState,
        token_network_id: TokenNetworkID,
        channel_id: ChannelID,
) -> Optional[NettingChannelState]:
    """ Return the NettingChannelState if it exists, None otherwise. """
    token_network = get_token_network_by_identifier(
        chain_state,
        token_network_id,
    )

    channel_state = None
    if token_network:
        channel_state = token_network.channelidentifiers_to_channels.get(channel_id)

    return channel_state


def get_channelstate_by_id(
        chain_state: ChainState,
        payment_network_id: PaymentNetworkID,
        token_address: TokenAddress,
        channel_id: ChannelID,
) -> Optional[NettingChannelState]:
    token_network = get_token_network_by_token_address(
        chain_state=chain_state,
        payment_network_id=payment_network_id,
        token_address=token_address,
    )

    channel_state = None
    if token_network:
        channel_state = token_network.channelidentifiers_to_channels.get(channel_id)

    return channel_state


def get_channelstate_filter(
        chain_state: ChainState,
        payment_network_id: PaymentNetworkID,
        token_address: TokenAddress,
        filter_fn: Callable,
) -> List[NettingChannelState]:
    """ Return the state of channels that match the condition in `filter_fn` """
    token_network = get_token_network_by_token_address(
        chain_state,
        payment_network_id,
        token_address,
    )

    result = []
    for channel_state in token_network.channelidentifiers_to_channels.values():
        if filter_fn(channel_state):
            result.append(channel_state)
    return result


def get_channelstate_open(
        chain_state: ChainState,
        payment_network_id: PaymentNetworkID,
        token_address: TokenAddress,
) -> List[NettingChannelState]:
    """Return the state of open channels in a token network."""
    return get_channelstate_filter(
        chain_state,
        payment_network_id,
        token_address,
        lambda channel_state: channel.get_status(channel_state) == CHANNEL_STATE_OPENED,
    )


def get_channelstate_closing(
        chain_state: ChainState,
        payment_network_id: PaymentNetworkID,
        token_address: TokenAddress,
) -> List[NettingChannelState]:
    """Return the state of closing channels in a token network."""
    return get_channelstate_filter(
        chain_state,
        payment_network_id,
        token_address,
        lambda channel_state: channel.get_status(channel_state) == CHANNEL_STATE_CLOSING,
    )


def get_channelstate_closed(
        chain_state: ChainState,
        payment_network_id: PaymentNetworkID,
        token_address: TokenAddress,
) -> List[NettingChannelState]:
    """Return the state of closed channels in a token network."""
    return get_channelstate_filter(
        chain_state,
        payment_network_id,
        token_address,
        lambda channel_state: channel.get_status(channel_state) == CHANNEL_STATE_CLOSED,
    )


def get_channelstate_settling(
        chain_state: ChainState,
        payment_network_id: PaymentNetworkID,
        token_address: TokenAddress,
) -> List[NettingChannelState]:
    """Return the state of settling channels in a token network."""
    return get_channelstate_filter(
        chain_state,
        payment_network_id,
        token_address,
        lambda channel_state: channel.get_status(channel_state) == CHANNEL_STATE_SETTLING,
    )


def get_channelstate_settled(
        chain_state: ChainState,
        payment_network_id: PaymentNetworkID,
        token_address: TokenAddress,
) -> List[NettingChannelState]:
    """Return the state of settled channels in a token network."""
    return get_channelstate_filter(
        chain_state,
        payment_network_id,
        token_address,
        lambda channel_state: channel.get_status(channel_state) == CHANNEL_STATE_SETTLED,
    )


def role_from_transfer_task(transfer_task: TransferTask) -> str:
    if isinstance(transfer_task, InitiatorTask):
        return 'initiator'
    elif isinstance(transfer_task, MediatorTask):
        return 'mediator'
    elif isinstance(transfer_task, TargetTask):
        return 'target'


def get_transfer_role(chain_state: ChainState, secrethash: SecretHash) -> str:
    return role_from_transfer_task(
        chain_state.payment_mapping.secrethashes_to_task.get(secrethash),
    )


def get_transfer_task(chain_state: ChainState, secrethash: SecretHash):
    return chain_state.payment_mapping.secrethashes_to_task.get(secrethash)


def get_all_transfer_tasks(chain_state: ChainState) -> Dict[SecretHash, TransferTask]:
    return chain_state.payment_mapping.secrethashes_to_task


def list_channelstate_for_tokennetwork(
        chain_state: ChainState,
        payment_network_id: PaymentNetworkID,
        token_address: TokenAddress,
) -> List[NettingChannelState]:

    token_network = get_token_network_by_token_address(
        chain_state,
        payment_network_id,
        token_address,
    )

    if token_network:
        result = list(token_network.channelidentifiers_to_channels.values())
    else:
        result = []

    return result


def list_all_channelstate(chain_state: ChainState) -> List[NettingChannelState]:
    result = []
    for payment_network in chain_state.identifiers_to_paymentnetworks.values():
        for token_network in payment_network.tokenidentifiers_to_tokennetworks.values():
            # TODO: Either enforce immutability or make a copy
            result.extend(token_network.channelidentifiers_to_channels.values())

    return result


def filter_channels_by_partneraddress(
        chain_state: ChainState,
        payment_network_id: PaymentNetworkID,
        token_address: TokenAddress,
        partner_addresses: List[Address],
) -> List[NettingChannelState]:

    token_network = get_token_network_by_token_address(
        chain_state,
        payment_network_id,
        token_address,
    )

    result = []
    for partner in partner_addresses:
        channels = [
            token_network.channelidentifiers_to_channels[channel_id]
            for channel_id in token_network.partneraddresses_to_channelidentifiers[partner]
        ]
        states = filter_channels_by_status(
            channels,
            [CHANNEL_STATE_UNUSABLE],
        )
        # If multiple channel states are found, return the last one.
        if states:
            result.append(states[-1])

    return result


def filter_channels_by_status(
        channel_states: List[NettingChannelState],
        exclude_states=None,
) -> List[NettingChannelState]:
    """ Filter the list of channels by excluding ones
    for which the state exists in `exclude_states`. """

    if exclude_states is None:
        exclude_states = []

    states = []
    for channel_state in channel_states:
        if channel.get_status(channel_state) not in exclude_states:
            states.append(channel_state)

    return states


def detect_balance_proof_change(
        old_state: State,
        current_state: State,
) -> Iterator[BalanceProofSignedState]:
    """ Compare two states for any received balance_proofs that are not in `old_state`. """
    if old_state == current_state:
        return
    for payment_network_identifier in current_state.identifiers_to_paymentnetworks:
        try:
            old_payment_network = old_state.identifiers_to_paymentnetworks.get(
                payment_network_identifier,
            )
        except AttributeError:
            old_payment_network = None
        current_payment_network = current_state.identifiers_to_paymentnetworks[
            payment_network_identifier
        ]
        if old_payment_network == current_payment_network:
            continue

        for token_network_identifier in current_payment_network.tokenidentifiers_to_tokennetworks:
            try:
                old_token_network = old_payment_network.tokenidentifiers_to_tokennetworks.get(
                    token_network_identifier,
                )
            except AttributeError:
                old_token_network = None
            current_token_network = current_payment_network.tokenidentifiers_to_tokennetworks[
                token_network_identifier
            ]
            if old_token_network == current_token_network:
                continue

            for channel_identifier in current_token_network.channelidentifiers_to_channels:
                try:
                    old_channel = old_token_network.channelidentifiers_to_channels.get(
                        channel_identifier,
                    )
                except AttributeError:
                    old_channel = None
                current_channel = current_token_network.channelidentifiers_to_channels[
                    channel_identifier
                ]
                if current_channel == old_channel:
                    continue

                elif (
                        current_channel.partner_state.balance_proof is not None and
                        (
                            old_channel is None or
                            old_channel.partner_state.balance_proof !=
                            current_channel.partner_state.balance_proof
                        )
                ):
                    yield current_channel.partner_state.balance_proof
