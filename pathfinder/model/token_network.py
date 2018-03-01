# -*- coding: utf-8 -*-
import collections
from itertools import islice
from typing import List

import networkx as nx
from eth_utils import is_checksum_address
from networkx import DiGraph

from pathfinder.config import EMPTY_MERKLE_ROOT
from pathfinder.model.balance_proof import BalanceProof
from pathfinder.model.channel_view import ChannelView
from pathfinder.model.lock import Lock
from pathfinder.utils.types import Address, ChannelId
from pathfinder.utils.crypto import (
    compute_merkle_tree,
    get_merkle_root
)


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
    """

    def __init__(
        self,
        token_address: Address,
        contract_address: Address,
        contract_deployment_block: int
    ):
        """
        Initializes a new TokenNetwork.
        """
        self.token_address = token_address
        self.contract_address = contract_address
        self.G = DiGraph()

    # Contract event listener functions

    def handle_channel_opened_event(self, channel_id: ChannelId):
        # TODO: do we need the timeout here?
        """
        Register the channel in the graph, add participents to graph if necessary.

        Corresponds to the ChannelOpened event. Called by the contract event listener.
        """
        view1, view2 = ChannelView.from_id(channel_id)

        assert is_checksum_address(view1.self)
        assert is_checksum_address(view2.self)
        assert view1.token == self.token_address
        assert view2.token == self.token_address

        self.G.add_edge(view1.self, view2.self, data=view1)
        self.G.add_edge(view2.self, view1.self, data=view2)

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
        view1, view2 = ChannelView.from_id(channel_id)

        assert is_checksum_address(view1.self)
        assert is_checksum_address(view2.self)
        assert view1.token == self.token_address
        assert view2.token == self.token_address

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
        # FIXME: directly recover sender and receiver addresses from channel IDs
        view1, view2 = ChannelView.from_id(balance_proof.channel_id)
        view: ChannelView = self.G[view1.self][view2.self]['data']

        assert view.transferred_amount < balance_proof.transferred_amount

        if locks:
            reconstructed_merkle_tree = compute_merkle_tree(lock.compute_hash() for lock in locks)
            reconstructed_merkle_root = get_merkle_root(reconstructed_merkle_tree)

            if not reconstructed_merkle_root == balance_proof.locksroot:
                raise ValueError('Supplied locks do not match the provided locksroot')
        else:
            if balance_proof.locksroot is not EMPTY_MERKLE_ROOT:
                raise ValueError('Locks specified but the lock Merkle tree is empty.')

        view.update_capacity(
            transferred_amount=balance_proof.transferred_amount,
            locked_amount=sum(lock.amount_locked for lock in locks)
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
