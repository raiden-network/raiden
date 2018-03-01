from typing import Tuple, Dict

from web3.contract import Contract

from pathfinder.utils.types import Address, ChannelId


class TokenNetworkContract(Contract):
    def get_channel_participants(self, channel_id: ChannelId) -> Tuple[Address, Address]:
        # FIXME: filter event log for participants on given channel ID
        return (None, None)

    def get_channel_deposits(self, channel_id: ChannelId) -> Dict[Address, int]:
        # FIXME: filter event log for deposits and topups on given channel ID
        return {None: None, None: None}

    def get_token_address(self) -> Address:
        return self.call().token()
