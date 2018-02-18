# -*- coding: utf-8 -*-

import collections
from itertools import islice

import networkx as nx


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

    def __init__(self, token_address, contract_address, contract_deployment_block):
        """
        Initializes a new TokenNetwork.
        """

    # Contract event listener functions

    def handle_channel_opened_event(self, channel_ident, participient1, participient2):
        # TODO: do we need the timeout here?
        """
        Register the channel in the graph, add participents to graph if necessary.

        Corresponds to the ChannelOpened event. Called by the contract event listener.
        """
        pass

    def handle_channel_new_balance_event(self, channel_ident, benificiary, balance):
        """
        Register a new balance for the benificiary.

        Corresponds to the ChannelNewBalance event. Called by the contract event listener.
        """
        pass

    def handle_channel_closed_event(self, channel_ident):
        """
        Close a channel. This doesn't mean that the channel is settled yet, but it cannot transfer any more.

        Corresponds to the ChannelClosed event. Called by the contract event listener.
        """
        pass

    def handle_channel_settled_event(self, channel_ident):
        """
        Settle a channel. This is nonessential as 'close_channel' has already removed the channel from the graph.

        TODO: do we need this?

        Corresponds to the ChannelSettled event. Called by the contract event listener.
        """
        pass

    # pathfinding endpoints

    def update_balance(self, channel_ident, balance_proof):
        """
        Update the channel balance with the new balance proof.
        This needs to check that the balance proof is valid.

        Called by the public interface.
        """
        pass

    def update_fee(self, channel_ident, new_fee, signature):
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
        Serializes the token network so it doesn't need to sync from scratch when the snapshot is loaded

        We probably need to save the lasts synced block here.
        """
        pass

    @staticmethod
    def load_snapshot(filename):
        """
        Deserializes the token network so it doesn't need to sync from scratch
        """
        pass
