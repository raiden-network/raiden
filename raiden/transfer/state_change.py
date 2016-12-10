# -*- coding: utf-8 -*-
from raiden.transfer.architecture import StateChange
# pylint: disable=too-few-public-methods,too-many-arguments,too-many-instance-attributes


class Blocknumber(StateChange):
    """ Transition used when a new block is mined.

    Args:
        block_number: The current block_number.
    """
    def __init__(self, block_number):
        self.block_number = block_number


class Route(StateChange):
    """ Route state for the same asset as `transfer_id`. """
    def __init__(self,
                 transfer_id,
                 state,
                 node_address,
                 capacity,
                 settle_timeout,
                 reveal_timeout):

        self.transfer_id = transfer_id
        self.state = state
        self.node_address = node_address
        self.capacity = capacity
        self.settle_timeout = settle_timeout
        self.reveal_timeout = reveal_timeout
