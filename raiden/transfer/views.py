from raiden.transfer import channel
from raiden.transfer.architecture import ContractSendEvent, TransferTask
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.mediated_transfer.tasks import InitiatorTask, MediatorTask, TargetTask
from raiden.transfer.state import (
    BalanceProofSignedState,
    BalanceProofUnsignedState,
    ChainState,
    ChannelState,
    NettingChannelState,
    NetworkState,
    QueueIdsToQueues,
    TokenNetworkRegistryState,
    TokenNetworkState,
)
from raiden.utils.typing import (
    MYPY_ANNOTATION,
    TYPE_CHECKING,
    Address,
    BlockNumber,
    Callable,
    Dict,
    Iterator,
    List,
    Optional,
    Secret,
    SecretHash,
    Set,
    TokenAddress,
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
    Tuple,
    Union,
)

if TYPE_CHECKING:
    from raiden.app import App  # pylint: disable=unused-import
    from raiden.raiden_service import RaidenService  # pylint: disable=unused-import

# TODO: Either enforce immutability or make a copy of the values returned by
#     the view functions


def all_neighbour_nodes(chain_state: ChainState) -> Set[Address]:
    """ Return the identifiers for all nodes accross all token network registries which
    have a channel open with this one.
    """
    addresses = set()

    for token_network_registry in chain_state.identifiers_to_tokennetworkregistries.values():
        for (
            token_network
        ) in token_network_registry.tokennetworkaddresses_to_tokennetworks.values():
            channel_states = token_network.channelidentifiers_to_channels.values()
            for channel_state in channel_states:
                addresses.add(channel_state.partner_state.address)

    return addresses


def block_number(chain_state: ChainState) -> BlockNumber:
    return chain_state.block_number


def count_token_network_channels(
    chain_state: ChainState,
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
) -> int:
    token_network = get_token_network_by_token_address(
        chain_state, token_network_registry_address, token_address
    )

    if token_network is not None:
        count = len(token_network.network_graph.network)
    else:
        count = 0

    return count


def state_from_raiden(raiden: "RaidenService") -> ChainState:  # pragma: no unittest
    assert raiden.wal, "raiden.wal not set"
    # TODO: current_state should not be optional
    return raiden.wal.state_manager.current_state  # type: ignore


def state_from_app(app: "App") -> ChainState:  # pragma: no unittest
    return state_from_raiden(app.raiden)


def get_pending_transactions(chain_state: ChainState) -> List[ContractSendEvent]:
    return chain_state.pending_transactions


def get_all_messagequeues(chain_state: ChainState) -> QueueIdsToQueues:
    return chain_state.queueids_to_queues


def get_networkstatuses(chain_state: ChainState) -> Dict:
    return chain_state.nodeaddresses_to_networkstates


def get_node_network_status(chain_state: ChainState, node_address: Address) -> NetworkState:
    return chain_state.nodeaddresses_to_networkstates.get(node_address, NetworkState.UNKNOWN)


def get_participants_addresses(
    chain_state: ChainState,
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
) -> Set[Address]:
    token_network = get_token_network_by_token_address(
        chain_state, token_network_registry_address, token_address
    )

    if token_network is not None:
        addresses = set(token_network.network_graph.network.nodes())
    else:
        addresses = set()

    return addresses


def get_our_deposits_for_token_network(
    chain_state: ChainState,
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
) -> int:
    open_channels = get_channelstate_open(
        chain_state, token_network_registry_address, token_address
    )

    total_deposit = 0
    for channel_state in open_channels:
        total_deposit += channel_state.our_state.contract_balance

    return total_deposit


def get_token_network_registry_address(
    chain_state: ChainState
) -> List[TokenNetworkRegistryAddress]:
    return list(chain_state.identifiers_to_tokennetworkregistries.keys())


def get_token_network_registry_by_token_network_address(
    chain_state: ChainState, token_network_address: TokenNetworkAddress
) -> Optional[TokenNetworkRegistryState]:
    for token_network_registry in chain_state.identifiers_to_tokennetworkregistries.values():
        if token_network_address in token_network_registry.tokennetworkaddresses_to_tokennetworks:
            return token_network_registry

    return None


def get_token_network_address_by_token_address(
    chain_state: ChainState,
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
) -> Optional[TokenNetworkAddress]:
    token_network = get_token_network_by_token_address(
        chain_state, token_network_registry_address, token_address
    )

    token_network_address = getattr(token_network, "address", None)

    return token_network_address


def get_token_network_addresses(
    chain_state: ChainState, token_network_registry_address: TokenNetworkRegistryAddress
) -> List[TokenNetworkAddress]:
    """ Return the list of token networks registered with the given token network registry. """
    token_network_registry = chain_state.identifiers_to_tokennetworkregistries.get(
        token_network_registry_address
    )

    if token_network_registry is not None:
        token_networks = token_network_registry.tokennetworkaddresses_to_tokennetworks.values()
        return [token_network.address for token_network in token_networks]

    return list()


def get_token_identifiers(
    chain_state: ChainState, token_network_registry_address: TokenNetworkRegistryAddress
) -> List[TokenAddress]:
    """ Return the list of tokens registered with the given token network registry. """
    token_network_registry = chain_state.identifiers_to_tokennetworkregistries.get(
        token_network_registry_address
    )

    if token_network_registry is not None:
        token_addresses = token_network_registry.tokenaddresses_to_tokennetworkaddresses.keys()
        return [token_address for token_address in token_addresses]

    return list()


def total_token_network_channels(
    chain_state: ChainState,
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
) -> int:

    token_network = get_token_network_by_token_address(
        chain_state, token_network_registry_address, token_address
    )

    result = 0
    if token_network:
        result = len(token_network.channelidentifiers_to_channels)

    return result


def get_token_network_by_token_address(
    chain_state: ChainState,
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
) -> Optional[TokenNetworkState]:

    token_network_registry = chain_state.identifiers_to_tokennetworkregistries.get(
        token_network_registry_address
    )

    if token_network_registry is not None:
        token_network_address = token_network_registry.tokenaddresses_to_tokennetworkaddresses.get(
            token_address
        )

        if token_network_address:
            return token_network_registry.tokennetworkaddresses_to_tokennetworks.get(
                token_network_address
            )

    return None


def get_token_network_by_address(
    chain_state: ChainState, token_network_address: TokenNetworkAddress
) -> Optional[TokenNetworkState]:

    token_network_state = None
    for token_network_registry_state in chain_state.identifiers_to_tokennetworkregistries.values():
        networks_by_address = token_network_registry_state.tokennetworkaddresses_to_tokennetworks
        token_network_state = networks_by_address.get(token_network_address)
        if token_network_state:
            return token_network_state

    return token_network_state


def get_channelstate_for(
    chain_state: ChainState,
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
    partner_address: Address,
) -> Optional[NettingChannelState]:
    """ Return the NettingChannelState if it exists, None otherwise. """
    token_network = get_token_network_by_token_address(
        chain_state, token_network_registry_address, token_address
    )

    channel_state = None
    if token_network:
        channels = [
            token_network.channelidentifiers_to_channels[channel_id]
            for channel_id in token_network.partneraddresses_to_channelidentifiers[partner_address]
        ]
        states = filter_channels_by_status(channels, [ChannelState.STATE_UNUSABLE])
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
        states = filter_channels_by_status(channels, [ChannelState.STATE_UNUSABLE])
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
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
    filter_fn: Callable,
) -> List[NettingChannelState]:
    """ Return the state of channels that match the condition in `filter_fn` """
    token_network = get_token_network_by_token_address(
        chain_state, token_network_registry_address, token_address
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
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
) -> List[NettingChannelState]:
    """Return the state of open channels in a token network."""
    return get_channelstate_filter(
        chain_state,
        token_network_registry_address,
        token_address,
        lambda channel_state: channel.get_status(channel_state) == ChannelState.STATE_OPENED,
    )


def get_channelstate_closing(
    chain_state: ChainState,
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
) -> List[NettingChannelState]:
    """Return the state of closing channels in a token network."""
    return get_channelstate_filter(
        chain_state,
        token_network_registry_address,
        token_address,
        lambda channel_state: channel.get_status(channel_state) == ChannelState.STATE_CLOSING,
    )


def get_channelstate_closed(
    chain_state: ChainState,
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
) -> List[NettingChannelState]:
    """Return the state of closed channels in a token network."""
    return get_channelstate_filter(
        chain_state,
        token_network_registry_address,
        token_address,
        lambda channel_state: channel.get_status(channel_state) == ChannelState.STATE_CLOSED,
    )


def get_channelstate_settling(
    chain_state: ChainState,
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
) -> List[NettingChannelState]:
    """Return the state of settling channels in a token network."""
    return get_channelstate_filter(
        chain_state,
        token_network_registry_address,
        token_address,
        lambda channel_state: channel.get_status(channel_state) == ChannelState.STATE_SETTLING,
    )


def get_channelstate_settled(
    chain_state: ChainState,
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
) -> List[NettingChannelState]:
    """Return the state of settled channels in a token network."""
    return get_channelstate_filter(
        chain_state,
        token_network_registry_address,
        token_address,
        lambda channel_state: channel.get_status(channel_state) == ChannelState.STATE_SETTLED,
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

    transfer_state = transfer_task.manager_state.initiator_transfers.get(secrethash)

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
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
) -> List[NettingChannelState]:

    token_network = get_token_network_by_token_address(
        chain_state, token_network_registry_address, token_address
    )

    if token_network:
        result = list(token_network.channelidentifiers_to_channels.values())
    else:
        result = []

    return result


def list_all_channelstate(chain_state: ChainState) -> List[NettingChannelState]:
    result: List[NettingChannelState] = []
    for token_network_registry in chain_state.identifiers_to_tokennetworkregistries.values():
        for (
            token_network
        ) in token_network_registry.tokennetworkaddresses_to_tokennetworks.values():
            # TODO: Either enforce immutability or make a copy
            result.extend(token_network.channelidentifiers_to_channels.values())

    return result


def filter_channels_by_partneraddress(
    chain_state: ChainState,
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
    partner_addresses: List[Address],
) -> List[NettingChannelState]:

    token_network = get_token_network_by_token_address(
        chain_state, token_network_registry_address, token_address
    )

    result: List[NettingChannelState] = []
    if not token_network:
        return result

    for partner in partner_addresses:
        channels = [
            token_network.channelidentifiers_to_channels[channel_id]
            for channel_id in token_network.partneraddresses_to_channelidentifiers[partner]
        ]
        states = filter_channels_by_status(channels, [ChannelState.STATE_UNUSABLE])
        # If multiple channel states are found, return the last one.
        if states:
            result.append(states[-1])

    return result


def filter_channels_by_status(
    channel_states: List[NettingChannelState], exclude_states: Optional[List[ChannelState]] = None
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
    for token_network_registry_address in current_state.identifiers_to_tokennetworkregistries:
        try:
            old_registry = old_state.identifiers_to_tokennetworkregistries.get(
                token_network_registry_address
            )
        except AttributeError:
            old_registry = None

        current_registry = current_state.identifiers_to_tokennetworkregistries[
            token_network_registry_address
        ]
        if old_registry == current_registry:
            continue

        for token_network_address in current_registry.tokennetworkaddresses_to_tokennetworks:
            if old_registry:
                old_token_network = old_registry.tokennetworkaddresses_to_tokennetworks.get(
                    token_network_address
                )
            else:
                old_token_network = None

            current_token_network = current_registry.tokennetworkaddresses_to_tokennetworks[
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
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_address: TokenAddress,
) -> Tuple[Optional[TokenNetworkRegistryState], Optional[TokenNetworkState]]:
    token_network_state = None
    tn_registry_state = chain_state.identifiers_to_tokennetworkregistries.get(
        token_network_registry_address
    )

    if tn_registry_state:
        token_network_address = tn_registry_state.tokenaddresses_to_tokennetworkaddresses.get(
            token_address
        )

        if token_network_address:
            token_network_state = tn_registry_state.tokennetworkaddresses_to_tokennetworks.get(
                token_network_address
            )

    return tn_registry_state, token_network_state
