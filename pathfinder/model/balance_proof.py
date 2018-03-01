from pathfinder.utils.types import ChannelId, Address


class BalanceProof:
    def __init__(
        self,
        nonce: int,
        transferred_amount: int,
        locksroot: bytes,
        channel_id: ChannelId,
        token_network_contract: Address,
        additional_hash: bytes,
        signature: bytes
    ):
        self.nonce = nonce
        self.transferred_amount = transferred_amount
        self.locksroot = locksroot
        self.channel_id = channel_id
        self.token_network_contract = token_network_contract
        self.additional_hash = additional_hash
        self.signature = signature
        self.sender = self._recover_sender()

    def _recover_sender(self) -> Address:
        # TODO: reconstruct balance proof message and ecrecover
        return None
