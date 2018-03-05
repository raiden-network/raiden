# -*- coding: utf-8 -*-
import collections
from itertools import islice
from typing import List

import networkx as nx
from eth_utils import is_checksum_address, is_same_address, to_checksum_address
from networkx import DiGraph

from pathfinder.contract.token_network_contract import TokenNetworkContract
from pathfinder.model.balance_proof import BalanceProof
from pathfinder.model.channel_view import ChannelView
from pathfinder.model.lock import Lock
from pathfinder.model.network_cache import NetworkCache
from pathfinder.utils.crypto import compute_merkle_tree, get_merkle_root
from pathfinder.utils.types import Address, ChannelId


def k_shortest_paths(G, source, target, k, weight=None):
    return list(islice(nx.shortest_simple_paths(G, source, target, weight=weight), k))


Balance = collections.namedtuple(
    'Balance',
    ['deposit_a', 'deposit_b',
     'received_a', 'received_b',
     'locked_a', 'locked_b',
     'available_a', 'available_b']
)


class TokenNetwork:
    """
    Manages a token network for pathfinding.

    Problems:
    - Do we set a default fee? Otherwise we estimate all opened channels with a zero fee.
      The other options to just take channels into account once a fee has been set.
    - Are fees absolute or relative to the transferred value (or base + relative)?
    - Can we somehow incorporate locked amounts from channels?
    - Do we represent the state as a undirected graph or directed graph
    TODO: test all these methods once we have sample data, DO NOT let these crucial functions
    remain uncovered!
    """

    def __init__(
        self,
        token_network_contract: TokenNetworkContract
    ):
        """
        Initializes a new TokenNetwork.
        """
        self.token_network_contract = token_network_contract
        self.address = to_checksum_address(self.token_network_contract.address)
        self.token_address = self.token_network_contract.get_token_address()
        self.network_cache = NetworkCache(self.token_network_contract)
        self.G = DiGraph()

    # Contract event listener functions

    def handle_channel_opened_event(self, channel_id: ChannelId):
        # TODO: do we need the timeout here?
        """
        Register the channel in the graph, add participents to graph if necessary.

        Corresponds to the ChannelOpened event. Called by the contract event listener.
        """
        view1, view2 = ChannelView.from_id(self.network_cache, channel_id)

        assert is_checksum_address(view1.self)
        assert is_checksum_address(view2.self)

        self.G.add_edge(view1.self, view2.self, view=view1)
        self.G.add_edge(view2.self, view1.self, view=view2)

    def handle_channel_new_balance_event(
        self,
        channel_id: ChannelId,
        receiver: Address,
        balance: int
    ):
        """
        Register a new balance for the beneficiary.

        Corresponds to the ChannelNewBalance event. Called by the contract event listener.
        """
        pass

    def handle_channel_closed_event(self, channel_id: ChannelId):
        """
        Close a channel. This doesn't mean that the channel is settled yet, but it cannot transfer
        any more.

        Corresponds to the ChannelClosed event. Called by the contract event listener.
        """
        view1, view2 = ChannelView.from_id(self.network_cache, channel_id)

        assert is_checksum_address(view1.self)
        assert is_checksum_address(view2.self)

        self.G.remove_edge(view1.self, view2.self)
        self.G.remove_edge(view2.self, view1.self)

    # pathfinding endpoints

    def update_balance(
        self,
        balance_proof: BalanceProof,
        locks: List[Lock]
    ):
        """
        Update the channel balance with the new balance proof.
        This needs to check that the balance proof is valid.

        Called by the public interface.
        """
        participant1, participant2 = self.token_network_contract.get_channel_participants(
            balance_proof.channel_id
        )
        if is_same_address(participant1, balance_proof.sender):
            receiver = participant2
        elif is_same_address(participant2, balance_proof.sender):
            receiver = participant1
        else:
            raise ValueError('Balance proof signature does not match any of the participants.')

        view1: ChannelView = self.G[balance_proof.sender][receiver]['view']
        view2: ChannelView = self.G[receiver][balance_proof.sender]['view']

        if view1.transferred_amount >= balance_proof.transferred_amount:
            # FIXME: use nonce instead for this check?
            raise ValueError('Balance proof is outdated.')

        reconstructed_merkle_tree = compute_merkle_tree(lock.compute_hash() for lock in locks)
        reconstructed_merkle_root = get_merkle_root(reconstructed_merkle_tree)

        if not reconstructed_merkle_root == balance_proof.locksroot:
            raise ValueError('Supplied locks do not match the provided locksroot')

        view1.update_capacity(
            transferred_amount=balance_proof.transferred_amount,
            locked_amount=sum(lock.amount_locked for lock in locks)
        )
        view2.update_capacity(
            received_amount=balance_proof.transferred_amount
        )

    def update_fee(self, channel_id: ChannelId, new_fee, signature):
        """
        Update the channel fee.
        This needs to check that the signature is valid.

        Called by the public interface.
        """
        pass

    def get_paths(self, from_address, to_address, value, num_paths, extra_data):
        """
        Returns at most num_paths paths for the payment.

        Called by the public interface.
        """
        pass

    # functions for persistence

    def save_snapshot(self, filename):
        """
        Serializes the token network so it doesn't need to sync from scratch when the snapshot is
        loaded.

        We probably need to save the lasts synced block here.
        """
        pass

    @staticmethod
    def load_snapshot(filename):
        """
        Deserializes the token network so it doesn't need to sync from scratch
        """
        pass
