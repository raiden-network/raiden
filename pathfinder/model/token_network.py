import logging
from typing import List, Dict, Any, Tuple

import networkx as nx
from networkx import DiGraph
from eth_utils import is_checksum_address, is_same_address
from raiden_libs.types import Address, ChannelIdentifier

from pathfinder.config import (
    DIVERSITY_PEN_DEFAULT,
    MIN_PATH_REDUNDANCY,
    PATH_REDUNDANCY_FACTOR,
    MAX_PATHS_PER_REQUEST
)
from pathfinder.model import ChannelView


log = logging.getLogger(__name__)


class TokenNetwork:
    """ Manages a token network for pathfinding. """

    def __init__(self, token_network_address: Address) -> None:
        """ Initializes a new TokenNetwork. """

        self.address = token_network_address
        self.channel_id_to_addresses: Dict[ChannelIdentifier, Tuple[Address, Address]] = dict()
        self.G = DiGraph()
        self.max_relative_fee = 0

    #
    # Contract event listener functions
    #
    def handle_channel_opened_event(
        self,
        channel_identifier: ChannelIdentifier,
        participant1: Address,
        participant2: Address,
    ):
        """ Register the channel in the graph, add participents to graph if necessary.

        Corresponds to the ChannelOpened event. Called by the contract event listener. """

        assert is_checksum_address(participant1)
        assert is_checksum_address(participant2)

        self.channel_id_to_addresses[channel_identifier] = (participant1, participant2)

        view1 = ChannelView(channel_identifier, participant1, participant2, deposit=0)
        view2 = ChannelView(channel_identifier, participant2, participant1, deposit=0)

        self.G.add_edge(participant1, participant2, view=view1)
        self.G.add_edge(participant2, participant1, view=view2)

    def handle_channel_new_deposit_event(
        self,
        channel_identifier: ChannelIdentifier,
        receiver: Address,
        total_deposit: int
    ):
        """ Register a new balance for the beneficiary.

        Corresponds to the ChannelNewDeposit event. Called by the contract event listener. """

        assert is_checksum_address(receiver)

        try:
            participant1, participant2 = self.channel_id_to_addresses[channel_identifier]

            if receiver == participant1:
                self.G[participant1][participant2]['view'].update_capacity(deposit=total_deposit)
            elif receiver == participant2:
                self.G[participant2][participant1]['view'].update_capacity(deposit=total_deposit)
            else:
                log.error(
                    "Receiver in ChannelNewDeposit does not fit the internal channel"
                )
        except KeyError:
            log.error(
                "Received ChannelNewDeposit event for unknown channel '{}'".format(
                    channel_identifier
                )
            )

    def handle_channel_closed_event(self, channel_identifier: ChannelIdentifier):
        """ Close a channel. This doesn't mean that the channel is settled yet, but it cannot
        transfer any more.

        Corresponds to the ChannelClosed event. Called by the contract event listener. """

        try:
            # we need to unregister the channel_id here
            participant1, participant2 = self.channel_id_to_addresses.pop(channel_identifier)

            self.G.remove_edge(participant1, participant2)
            self.G.remove_edge(participant2, participant1)
        except KeyError:
            log.error(
                "Received ChannelClosed event for unknown channel '{}'".format(
                    channel_identifier
                )
            )

    #
    # pathfinding endpoints
    #
    def update_balance(
        self,
        channel_identifier: ChannelIdentifier,
        signer: Address,
        nonce: int,
        transferred_amount: int,
        locked_amount: int,
    ):
        """ Update the channel balance with the new balance proof.
        This needs to check that the balance proof is valid.

        Called by the public interface. """

        participant1, participant2 = self.channel_id_to_addresses.get(
            channel_identifier,
            (None, None)
        )

        if is_same_address(participant1, signer):
            receiver = participant2
        elif is_same_address(participant2, signer):
            receiver = participant1
        else:
            raise ValueError('Balance proof signature does not match any of the participants.')

        view1: ChannelView = self.G[signer][receiver]['view']
        view2: ChannelView = self.G[receiver][signer]['view']

        if nonce <= view1.balance_proof_nonce:
            raise ValueError('Outdated balance proof.')

        view1.update_capacity(
            nonce=nonce,
            transferred_amount=transferred_amount,
            locked_amount=locked_amount
        )
        view2.update_capacity(
            received_amount=transferred_amount
        )

    def update_fee(
        self,
        channel_identifier: ChannelIdentifier,
        signer: Address,
        nonce: int,
        relative_fee: int,
    ):
        """ Update the channel with a new fee.

        Validation of the data must happen before this method is called.
        """

        participant1, participant2 = self.channel_id_to_addresses.get(
            channel_identifier,
            (None, None)
        )
        if is_same_address(participant1, signer):
            sender = participant1
            receiver = participant2
        elif is_same_address(participant2, signer):
            sender = participant2
            receiver = participant1
        else:
            raise ValueError('Fee update signature does not match any of the participants.')

        channel_view: ChannelView = self.G[sender][receiver]['view']

        if nonce <= channel_view.fee_info_nonce:
            raise ValueError('Outdated fee info.')

        if relative_fee >= self.max_relative_fee:
            # Equal case is included to avoid a recalculation of the max fee.
            self.max_relative_fee = relative_fee
            channel_view._relative_fee = relative_fee
        elif channel_view._relative_fee == self.max_relative_fee:
            # O(n) operation but rarely called, amortized likely constant.
            channel_view._relative_fee = relative_fee
            self.max_relative_fee = max(
                edge_data['view'].relative_fee
                for _, _, edge_data in self.G.edges(data=True)
            )

        channel_view.update_fee(nonce, relative_fee)

    def get_paths(
        self,
        source: Address,
        target: Address,
        value: int,
        k: int,
        **kwargs
    ):
        k = min(k, MAX_PATHS_PER_REQUEST)
        visited: Dict[ChannelIdentifier, float] = {}
        paths: List[List[Address]] = []
        hop_bias = kwargs.get('hop_bias', 0)
        assert 0 <= hop_bias <= 1

        def weight(
            u: Address,
            v: Address,
            attr: Dict[str, Any]
        ):
            view: ChannelView = attr['view']
            if view.capacity < value:
                return None
            else:
                return hop_bias * self.max_relative_fee + \
                       (1 - hop_bias) * view._relative_fee + \
                       visited.get(
                            view.channel_id,
                            0
                       )

        max_iterations = max(MIN_PATH_REDUNDANCY, PATH_REDUNDANCY_FACTOR * k)
        for _ in range(max_iterations):
            path = nx.dijkstra_path(self.G, source, target, weight=weight)
            duplicate = path in paths
            for node1, node2 in zip(path[:-1], path[1:]):
                channel_id = self.G[node1][node2]['view'].channel_id
                if duplicate:
                    visited[channel_id] *= 2
                else:
                    visited[channel_id] = visited.get(channel_id, 0) + DIVERSITY_PEN_DEFAULT

            if not duplicate:
                paths.append(path)
            if len(paths) >= k:
                break

        result = []
        for path in paths:
            fee = 0
            for node1, node2 in zip(path[:-1], path[1:]):
                fee += self.G[node1][node2]['view'].relative_fee

            result.append(dict(
                path=path,
                estimated_fee=fee
            ))

        return result
