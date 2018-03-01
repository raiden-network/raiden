from typing import Tuple, Dict

from pathfinder.contract.token_network_contract import TokenNetworkContract
from pathfinder.utils.types import Address, ChannelId


class NetworkCache:
    """
    Caches network information that require slow log or function queries to the Ethereum node.
    """
    def __init__(self, token_network_contract: TokenNetworkContract):
        self.token_network_contract = token_network_contract
        self.channel_participants: Dict[ChannelId, Tuple[Address, Address]] = {}
        self.channel_deposits: Dict[ChannelId, Dict[Address, int]] = {}

    def get_channel_participants(self, channel_id: ChannelId) -> Tuple[Address, Address]:
        participants = self.channel_participants.get(channel_id)
        if participants is None:
            participants = self.token_network_contract.get_channel_participants(channel_id)
            self.channel_participants[channel_id] = participants
        return participants

    def get_channel_deposits(self, channel_id: ChannelId) -> Dict[Address, int]:
        deposits = self.channel_deposits.get(channel_id)
        if deposits is None:
            deposits = self.token_network_contract.get_channel_deposits(channel_id)
            self.channel_deposits = deposits
        return deposits

    def get_channel_deposit(self, channel_id: ChannelId, sender: Address):
        return self.get_channel_deposits(channel_id)[sender]
