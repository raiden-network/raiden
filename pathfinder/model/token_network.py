# -*- coding: utf-8 -*-
import logging
from typing import List, Dict, Any, Tuple
import networkx as nx
from coincurve import PublicKey
from coincurve.utils import sha256
from eth_utils import is_checksum_address, is_same_address, to_checksum_address
from networkx import DiGraph
from raiden_libs.utils import compute_merkle_tree, get_merkle_root, public_key_to_address
from web3.contract import Contract
from pathfinder.config import (
    DIVERSITY_PEN_DEFAULT,
    MIN_PATH_REDUNDANCY,
    PATH_REDUNDANCY_FACTOR,
    MAX_PATHS_PER_REQUEST
)
from pathfinder.model.balance_proof import BalanceProof
from pathfinder.model.channel_view import ChannelView
from pathfinder.model.lock import Lock
from pathfinder.utils.types import Address, ChannelId


log = logging.getLogger(__name__)


class TokenNetwork:
    """ Manages a token network for pathfinding.

    Problems:
    - Do we set a default fee? Otherwise we estimate all opened channels with a zero fee.
      The other options to just take channels into account once a fee has been set.
    - Are fees absolute or relative to the transferred value (or base + relative)?
    TODO: test all these methods once we have sample data, DO NOT let these crucial functions
    remain uncovered! """

    def __init__(
        self,
        token_network_contract: Contract
    ) -> None:
        """ Initializes a new TokenNetwork. """

        self.token_network_contract = token_network_contract
        self.address = to_checksum_address(self.token_network_contract.address)
        self.token_address = self.token_network_contract.functions.token().call()
        self.channel_id_to_addresses: Dict[int, Tuple[Address, Address]] = dict()
        self.G = DiGraph()
        self.max_fee = 0.0

    #
    # Contract event listener functions
    #

    def handle_channel_opened_event(
        self,
        channel_id: ChannelId,
        participant1: Address,
        participant2: Address,
    ):
        """ Register the channel in the graph, add participents to graph if necessary.

        Corresponds to the ChannelOpened event. Called by the contract event listener. """

        assert is_checksum_address(participant1)
        assert is_checksum_address(participant2)

        self.channel_id_to_addresses[channel_id] = (participant1, participant2)

        view1 = ChannelView(channel_id, participant1, participant2, deposit=0)
        view2 = ChannelView(channel_id, participant2, participant1, deposit=0)

        self.G.add_edge(participant1, participant2, view=view1)
        self.G.add_edge(participant2, participant1, view=view2)

    def handle_channel_new_deposit_event(
        self,
        channel_id: ChannelId,
        receiver: Address,
        total_deposit: int
    ):
        """ Register a new balance for the beneficiary.

        Corresponds to the ChannelNewDeposit event. Called by the contract event listener. """

        assert is_checksum_address(receiver)

        try:
            participant1, participant2 = self.channel_id_to_addresses[channel_id]

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
                    channel_id
                )
            )

    def handle_channel_closed_event(self, channel_id: ChannelId):
        """ Close a channel. This doesn't mean that the channel is settled yet, but it cannot
        transfer any more.

        Corresponds to the ChannelClosed event. Called by the contract event listener. """

        try:
            # we need to unregister the channel_id here
            participant1, participant2 = self.channel_id_to_addresses.pop(channel_id)

            self.G.remove_edge(participant1, participant2)
            self.G.remove_edge(participant2, participant1)
        except KeyError:
            log.error(
                "Received ChannelClosed event for unknown channel '{}'".format(
                    channel_id
                )
            )

    #
    # pathfinding endpoints
    #

    def update_balance(
        self,
        balance_proof: BalanceProof,
        locks: List[Lock]
    ):
        """ Update the channel balance with the new balance proof.
        This needs to check that the balance proof is valid.

        Called by the public interface. """

        participant1, participant2 = self.channel_id_to_addresses.get(
            balance_proof.channel_id,
            (None, None)
        )
        if is_same_address(participant1, balance_proof.sender):
            receiver = participant2
        elif is_same_address(participant2, balance_proof.sender):
            receiver = participant1
        else:
            raise ValueError('Balance proof signature does not match any of the participants.')

        view1: ChannelView = self.G[balance_proof.sender][receiver]['view']
        view2: ChannelView = self.G[receiver][balance_proof.sender]['view']

        if balance_proof.nonce <= view1.balance_proof_nonce:
            raise ValueError('Outdated balance proof.')

        reconstructed_merkle_tree = compute_merkle_tree(lock.compute_hash() for lock in locks)
        reconstructed_merkle_root = get_merkle_root(reconstructed_merkle_tree)

        if not reconstructed_merkle_root == balance_proof.locksroot:
            raise ValueError('Supplied locks do not match the provided locksroot')

        view1.update_capacity(
            balance_proof.nonce,
            transferred_amount=balance_proof.transferred_amount,
            locked_amount=sum(lock.amount_locked for lock in locks)
        )
        view2.update_capacity(
            received_amount=balance_proof.transferred_amount
        )

    def update_fee(
            self,
            channel_id: ChannelId,
            new_fee: bytes,
            signature: bytes
    ):
        """ Update the channel with a new fee. New_fee bytes are of the form '0.0012'.encode()"""
        # Fixme: I need a nonce for replay protection
        msg = new_fee
        signer = public_key_to_address(
            PublicKey.from_signature_and_message(
                signature,
                msg,
                hasher=sha256
            )
        )

        participant1, participant2 = self.channel_id_to_addresses.get(
            channel_id,
            (None, None)
        )
        if is_same_address(participant1, signer):
            sender = participant1
            receiver = participant2
        elif is_same_address(participant2, signer):
            sender = participant2
            receiver = participant1
        else:
            raise ValueError('Signature does not match any of the participants.')

        new_fee_casted = float(new_fee)
        channel_view = self.G[sender][receiver]['view']

        if new_fee_casted >= self.max_fee:
            # Equal case is included to avoid a recalculation of the max fee.
            self.max_fee = new_fee_casted
            channel_view.fee = new_fee_casted
        elif channel_view.fee == self.max_fee:
            # O(n) operation but rarely called, amortized likely constant.
            channel_view.fee = new_fee_casted
            self.max_fee = max(
                edge_data['view'].fee
                for _, _, edge_data in self.G.edges(data=True)
            )

        channel_view.fee = new_fee_casted

    def get_paths(
            self,
            source: Address,
            target: Address,
            value: int,
            k: int,
            **kwargs
    ):
        k = min(k, MAX_PATHS_PER_REQUEST)
        visited: Dict[ChannelId, float] = {}
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
                return hop_bias*self.max_fee + (1-hop_bias)*view.fee + visited.get(
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
                fee += self.G[node1][node2]['view'].fee

            result.append(dict(
                path=path,
                estimated_fee=fee
            ))

        return result
