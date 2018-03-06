import json
from typing import Tuple, Dict

import os
from web3.contract import Contract

from pathfinder.utils.types import Address, ChannelId


class TokenNetworkContract(Contract):
    def __init__(self, *args, **kwargs):
        abi_path = os.path.splitext(__file__)[0] + '.json'
        with open(abi_path) as abi_file:
            abi = json.load(abi_file)
        kwargs['abi'] = abi
        Contract.__init__(self, *args, **kwargs)

    def get_channel_participants(self, channel_id: ChannelId) -> Tuple[Address, Address]:
        # FIXME: filter event log for participants on given channel ID
        return (None, None)

    def get_channel_deposits(self, channel_id: ChannelId) -> Dict[Address, int]:
        # FIXME: filter event log for deposits and topups on given channel ID
        return {None: None, None: None}

    def get_token_address(self) -> Address:
        return self.call().token()
