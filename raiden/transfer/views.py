from raiden.transfer import channel
from raiden.transfer.architecture import ContractSendEvent, TransferTask
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.mediated_transfer.tasks import InitiatorTask, MediatorTask, TargetTask
from raiden.transfer.state import (
    CHANNEL_STATE_CLOSED,
    CHANNEL_STATE_CLOSING,
    CHANNEL_STATE_OPENED,
    CHANNEL_STATE_SETTLED,
    CHANNEL_STATE_SETTLING,
    CHANNEL_STATE_UNUSABLE,
    NODE_NETWORK_UNKNOWN,
    BalanceProofSignedState,
    BalanceProofUnsignedState,
    ChainState,
    NettingChannelState,
    PaymentNetworkState,
    QueueIdsToQueues,
    TokenNetworkState,
)
from raiden.utils.typing import (
    MYPY_ANNOTATION,
    Address,
    BlockNumber,
    Callable,
    Dict,
    Iterator,
    List,
    Optional,
    PaymentNetworkAddress,
    Secret,
    SecretHash,
    Set,
    TokenAddress,
    TokenNetworkAddress,
    Tuple,
    Union,
)

# TODO: Either enforce immutability or make a copy of the values returned by
#     the view functions


def all_neighbour_nodes(chain_state: ChainState) -> Set[Address]:
    """ Return the identifiers for all nodes accross all payment networks which
    have a channel open with this one.
    """
    addresses = set()

    for payment_network in chain_state.identifiers_to_paymentnetworks.values():
        for token_network in payment_network.tokennetworkaddresses_to_tokennetworks.values():
            channel_states = token_network.channelidentifiers_to_channels.values()
            for channel_state in channel_states:
                addresses.add(channel_state.partner_state.address)

    return addresses


def block_number(chain_state: ChainState) -> BlockNumber:
    return chain_state.block_number


def count_token_network_channels(
    chain_state: ChainState,
    payment_network_address: PaymentNetworkAddress,
    token_address: TokenAddress,
) -> int:
    token_network = get_token_network_by_token_address(
        chain_state, payment_network_address, token_address
    )

    if token_network is not None:
        count = len(token_network.network_graph.network)
    else:
        count = 0

    return count


def state_from_raiden(raiden) -> ChainState:  # pragma: no unittest
    return raiden.wal.state_manager.current_state


def state_from_app(app) -> ChainState:  # pragma: no unittest
    return app.raiden.wal.state_manager.current_state


def get_pending_transactions(chain_state: ChainState) -> List[ContractSendEvent]:
    return chain_state.pending_transactions


def get_all_messagequeues(chain_state: ChainState,) -> QueueIdsToQueues:
    return chain_state.queueids_to_queues


def get_networkstatuses(chain_state: ChainState) -> Dict:
    return chain_state.nodeaddresses_to_networkstates


def get_node_network_status(chain_state: ChainState, node_address: Address) -> str:

    return chain_state.nodeaddresses_to_networkstates.get(node_address, NODE_NETWORK_UNKNOWN)


def get_participants_addresses(
    chain_state: ChainState,
    payment_network_address: PaymentNetworkAddress,
    token_address: TokenAddress,
) -> Set[Address]:
    token_network = get_token_network_by_token_address(
        chain_state, payment_network_address, token_address
    )

    if token_network is not None:
        addresses = set(token_network.network_graph.network.nodes())
    else:
        addresses = set()

    return addresses


def get_our_deposits_for_token_network(
    chain_state: ChainState,
    payment_network_address: PaymentNetworkAddress,
    token_address: TokenAddress,
) -> int:
    open_channels = get_channelstate_open(chain_state, payment_network_address, token_address)

    total_deposit = 0
    for channel_state in open_channels:
        total_deposit += channel_state.our_state.contract_balance

    return total_deposit


def get_payment_network_address(chain_state: ChainState) -> List[PaymentNetworkAddress]:
    return list(chain_state.identifiers_to_paymentnetworks.keys())


def get_token_network_registry_by_token_network_address(
    chain_state: ChainState, token_network_address: TokenNetworkAddress
) -> Optional[PaymentNetworkState]:
    for payment_network in chain_state.identifiers_to_paymentnetworks.values():
        if token_network_address in payment_network.tokennetworkaddresses_to_tokennetworks:
            return payment_network

    return None


def get_token_network_address_by_token_address(
    chain_state: ChainState,
    payment_network_address: PaymentNetworkAddress,
    token_address: TokenAddress,
) -> Optional[TokenNetworkAddress]:
    token_network = get_token_network_by_token_address(
        chain_state, payment_network_address, token_address
    )

    token_network_address = getattr(token_network, "address", None)

    return token_network_address


def get_token_network_addresses(
    chain_state: ChainState, payment_network_address: PaymentNetworkAddress
) -> List[TokenNetworkAddress]:
    """ Return the list of token networks registered with the given payment network. """
    payment_network = chain_state.identifiers_to_paymentnetworks.get(payment_network_address)

    if payment_network is not None:
        return [
            token_network.address
            for token_network in payment_network.tokennetworkaddresses_to_tokennetworks.values()
        ]

    return list()


def get_token_identifiers(
    chain_state: ChainState, payment_network_address: PaymentNetworkAddress
) -> List[TokenAddress]:
    """ Return the list of tokens registered with the given payment network. """
    payment_network = chain_state.identifiers_to_paymentnetworks.get(payment_network_address)

    if payment_network is not None:
        return [
            token_address
            for token_address in payment_network.tokenaddresses_to_tokennetworkaddresses.keys()
        ]

    return list()


def total_token_network_channels(
    chain_state: ChainState,
    payment_network_address: PaymentNetworkAddress,
    token_address: TokenAddress,
) -> int:

    token_network = get_token_network_by_token_address(
        chain_state, payment_network_address, token_address
    )

    result = 0
    if token_network:
        result = len(token_network.channelidentifiers_to_channels)

    return result


def get_token_network_by_token_address(
    chain_state: ChainState,
    payment_network_address: PaymentNetworkAddress,
    token_address: TokenAddress,
) -> Optional[TokenNetworkState]:

    payment_network = chain_state.identifiers_to_paymentnetworks.get(payment_network_address)

    if payment_network is not None:
        token_network_address = payment_network.tokenaddresses_to_tokennetworkaddresses.get(
            token_address
        )

        if token_network_address:
            return payment_network.tokennetworkaddresses_to_tokennetworks.get(
                token_network_address
            )

    return None


def get_token_network_by_address(
    chain_state: ChainState, token_network_address: TokenNetworkAddress
) -> Optional[TokenNetworkState]:

    token_network_state = None
    for payment_network_state in chain_state.identifiers_to_paymentnetworks.values():
        token_network_state = payment_network_state.tokennetworkaddresses_to_tokennetworks.get(
            token_network_address
        )
        if token_network_state:
            return token_network_state

    return token_network_state


def get_channelstate_for(
    chain_state: ChainState,
    payment_network_address: PaymentNetworkAddress,
    token_address: TokenAddress,
    partner_address: Address,
) -> Optional[NettingChannelState]:
    """ Return the NettingChannelState if it exists, None otherwise. """
    token_network = get_token_network_by_token_address(
        chain_state, payment_network_address, token_address
    )

    channel_state = None
    if token_network:
        channels = [
            token_network.channelidentifiers_to_channels[channel_id]
            for channel_id in token_network.partneraddresses_to_channelidentifiers[partner_address]
        ]
        states = filter_channels_by_status(channels, [CHANNEL_STATE_UNUSABLE])
        # If multiple channel states are found, return the last one.
        if states:
            channel_state = states[-1]

    return channel_state


def get_channelstate_by_token_network_and_partner(
    chain_state: ChainState, token_network_address: TokenNetworkAddress, partner_address: Address
) -> Optional[NettingChannelState]:
    """ Return the NettingChannelState if it exists, None otherwise. """
    token_network = get_token_network_by_address(chain_state, token_network_address)

    channel_state = None
    if token_network:
        channels = [
            token_network.channelidentifiers_to_channels[channel_id]
            for channel_id in token_network.partneraddresses_to_channelidentifiers[partner_address]
        ]
        states = filter_channels_by_status(channels, [CHANNEL_STATE_UNUSABLE])
        if states:
            channel_state = states[-1]

    return channel_state


def get_channelstate_by_canonical_identifier(
    chain_state: ChainState, canonical_identifier: CanonicalIdentifier
) -> Optional[NettingChannelState]:
    """ Return the NettingChannelState if it exists, None otherwise. """
    token_network = get_token_network_by_address(
        chain_state, canonical_identifier.token_network_address
    )

    channel_state = None
    if token_network:
        channel_state = token_network.channelidentifiers_to_channels.get(
            canonical_identifier.channel_identifier
        )

    return channel_state


def get_channelstate_filter(
    chain_state: ChainState,
    payment_network_address: PaymentNetworkAddress,
    token_address: TokenAddress,
    filter_fn: Callable,
) -> List[NettingChannelState]:
    """ Return the state of channels that match the condition in `filter_fn` """
    token_network = get_token_network_by_token_address(
        chain_state, payment_network_address, token_address
    )

    result: List[NettingChannelState] = []
    if not token_network:
        return result

    for channel_state in token_network.channelidentifiers_to_channels.values():
        if filter_fn(channel_state):
            result.append(channel_state)

    return result


def get_channelstate_open(
    chain_state: ChainState,
    payment_network_address: PaymentNetworkAddress,
    token_address: TokenAddress,
) -> List[NettingChannelState]:
    """Return the state of open channels in a token network."""
    return get_channelstate_filter(
        chain_state,
        payment_network_address,
        token_address,
        lambda channel_state: channel.get_status(channel_state) == CHANNEL_STATE_OPENED,
    )


def get_channelstate_closing(
    chain_state: ChainState,
    payment_network_address: PaymentNetworkAddress,
    token_address: TokenAddress,
) -> List[NettingChannelState]:
    """Return the state of closing channels in a token network."""
    return get_channelstate_filter(
        chain_state,
        payment_network_address,
        token_address,
        lambda channel_state: channel.get_status(channel_state) == CHANNEL_STATE_CLOSING,
    )


def get_channelstate_closed(
    chain_state: ChainState,
    payment_network_address: PaymentNetworkAddress,
    token_address: TokenAddress,
) -> List[NettingChannelState]:
    """Return the state of closed channels in a token network."""
    return get_channelstate_filter(
        chain_state,
        payment_network_address,
        token_address,
        lambda channel_state: channel.get_status(channel_state) == CHANNEL_STATE_CLOSED,
    )


def get_channelstate_settling(
    chain_state: ChainState,
    payment_network_address: PaymentNetworkAddress,
    token_address: TokenAddress,
) -> List[NettingChannelState]:
    """Return the state of settling channels in a token network."""
    return get_channelstate_filter(
        chain_state,
        payment_network_address,
        token_address,
        lambda channel_state: channel.get_status(channel_state) == CHANNEL_STATE_SETTLING,
    )


def get_channelstate_settled(
    chain_state: ChainState,
    payment_network_address: PaymentNetworkAddress,
    token_address: TokenAddress,
) -> List[NettingChannelState]:
    """Return the state of settled channels in a token network."""
    return get_channelstate_filter(
        chain_state,
        payment_network_address,
        token_address,
        lambda channel_state: channel.get_status(channel_state) == CHANNEL_STATE_SETTLED,
    )


def role_from_transfer_task(transfer_task: TransferTask) -> str:
    """Return the role and type for the transfer. Throws an exception on error"""
    # pragma: no cover
    if isinstance(transfer_task, InitiatorTask):
        return "initiator"
    if isinstance(transfer_task, MediatorTask):
        return "mediator"
    if isinstance(transfer_task, TargetTask):
        return "target"

    raise ValueError("Argument to role_from_transfer_task is not a TransferTask")


def secret_from_transfer_task(
    transfer_task: TransferTask, secrethash: SecretHash
) -> Optional[Secret]:
    """Return the secret for the transfer, None on ABSENT_SECRET."""
    assert isinstance(transfer_task, InitiatorTask)

    transfer_state = transfer_task.manager_state.initiator_transfers[secrethash]

    if transfer_state is None:
        return None

    return transfer_state.transfer_description.secret


def get_transfer_role(chain_state: ChainState, secrethash: SecretHash) -> Optional[str]:
    """
    Returns 'initiator', 'mediator' or 'target' to signify the role the node has
    in a transfer. If a transfer task is not found for the secrethash then the
    function returns None
    """
    task = chain_state.payment_mapping.secrethashes_to_task.get(secrethash)
    if not task:
        return None
    return role_from_transfer_task(task)


def get_transfer_secret(chain_state: ChainState, secrethash: SecretHash) -> Optional[Secret]:
    transfer_task = chain_state.payment_mapping.secrethashes_to_task.get(secrethash)
    if transfer_task is None:
        return None
    return secret_from_transfer_task(transfer_task=transfer_task, secrethash=secrethash)


def get_all_transfer_tasks(chain_state: ChainState) -> Dict[SecretHash, TransferTask]:
    return chain_state.payment_mapping.secrethashes_to_task


def list_channelstate_for_tokennetwork(
    chain_state: ChainState,
    payment_network_address: PaymentNetworkAddress,
    token_address: TokenAddress,
) -> List[NettingChannelState]:

    token_network = get_token_network_by_token_address(
        chain_state, payment_network_address, token_address
    )

    if token_network:
        result = list(token_network.channelidentifiers_to_channels.values())
    else:
        result = []

    return result


def list_all_channelstate(chain_state: ChainState) -> List[NettingChannelState]:
    result: List[NettingChannelState] = []
    for payment_network in chain_state.identifiers_to_paymentnetworks.values():
        for token_network in payment_network.tokennetworkaddresses_to_tokennetworks.values():
            # TODO: Either enforce immutability or make a copy
            result.extend(token_network.channelidentifiers_to_channels.values())

    return result


def filter_channels_by_partneraddress(
    chain_state: ChainState,
    payment_network_address: PaymentNetworkAddress,
    token_address: TokenAddress,
    partner_addresses: List[Address],
) -> List[NettingChannelState]:

    token_network = get_token_network_by_token_address(
        chain_state, payment_network_address, token_address
    )

    result: List[NettingChannelState] = []
    if not token_network:
        return result

    for partner in partner_addresses:
        channels = [
            token_network.channelidentifiers_to_channels[channel_id]
            for channel_id in token_network.partneraddresses_to_channelidentifiers[partner]
        ]
        states = filter_channels_by_status(channels, [CHANNEL_STATE_UNUSABLE])
        # If multiple channel states are found, return the last one.
        if states:
            result.append(states[-1])

    return result


def filter_channels_by_status(
    channel_states: List[NettingChannelState], exclude_states: Optional[List[str]] = None
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
    old_state: ChainState, current_state: ChainState
) -> Iterator[Union[BalanceProofSignedState, BalanceProofUnsignedState]]:
    """ Compare two states for any received balance_proofs that are not in `old_state`. """
    if old_state == current_state:
        return
    for payment_network_address in current_state.identifiers_to_paymentnetworks:
        try:
            old_payment_network = old_state.identifiers_to_paymentnetworks.get(
                payment_network_address
            )
        except AttributeError:
            old_payment_network = None

        current_payment_network = current_state.identifiers_to_paymentnetworks[
            payment_network_address
        ]
        if old_payment_network == current_payment_network:
            continue

        for (
            token_network_address
        ) in current_payment_network.tokennetworkaddresses_to_tokennetworks:
            if old_payment_network:
                old_token_network = old_payment_network.tokennetworkaddresses_to_tokennetworks.get(
                    token_network_address
                )
            else:
                old_token_network = None

            current_token_network = current_payment_network.tokennetworkaddresses_to_tokennetworks[
                token_network_address
            ]
            if old_token_network == current_token_network:
                continue

            for channel_identifier in current_token_network.channelidentifiers_to_channels:
                if old_token_network:
                    old_channel = old_token_network.channelidentifiers_to_channels.get(
                        channel_identifier
                    )
                else:
                    old_channel = None

                current_channel = current_token_network.channelidentifiers_to_channels[
                    channel_identifier
                ]
                if current_channel == old_channel:
                    continue

                else:
                    partner_state_updated = (
                        current_channel.partner_state.balance_proof is not None
                        and (
                            old_channel is None
                            or old_channel.partner_state.balance_proof
                            != current_channel.partner_state.balance_proof
                        )
                    )

                    if partner_state_updated:
                        assert current_channel.partner_state.balance_proof, MYPY_ANNOTATION
                        yield current_channel.partner_state.balance_proof

                    our_state_updated = current_channel.our_state.balance_proof is not None and (
                        old_channel is None
                        or old_channel.our_state.balance_proof
                        != current_channel.our_state.balance_proof
                    )

                    if our_state_updated:
                        assert current_channel.our_state.balance_proof, MYPY_ANNOTATION
                        yield current_channel.our_state.balance_proof


def get_networks(
    chain_state: ChainState,
    payment_network_address: PaymentNetworkAddress,
    token_address: TokenAddress,
) -> Tuple[Optional[PaymentNetworkState], Optional[TokenNetworkState]]:
    token_network_state = None
    payment_network_state = chain_state.identifiers_to_paymentnetworks.get(payment_network_address)

    if payment_network_state:
        token_network_address = payment_network_state.tokenaddresses_to_tokennetworkaddresses.get(
            token_address
        )

        if token_network_address:
            token_network_state = payment_network_state.tokennetworkaddresses_to_tokennetworks.get(
                token_network_address
            )

    return payment_network_state, token_network_state
