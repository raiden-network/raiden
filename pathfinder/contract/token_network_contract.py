from typing import Dict, Tuple

from web3.contract import Contract

from pathfinder.utils.types import Address, ChannelId


class TokenNetworkContract:
    def __init__(self, contract: Contract):
        self.contract = contract
        self.address = self.contract.address

    def __repr__(self):
        return '<TokenNetworkContract addr={}>'.format(self.address)

    def get_channel_participants(self, channel_id: ChannelId) -> Tuple[Address, Address]:
        # FIXME: filter event log for participants on given channel ID
        return (None, None)

    def get_channel_deposits(self, channel_id: ChannelId) -> Dict[Address, int]:
        # FIXME: filter event log for deposits and topups on given channel ID
        return {None: None, None: None}

    def get_token_address(self) -> Address:
        return self.contract.functions.token().call()
