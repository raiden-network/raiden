from pathfinder.utils.exceptions import InvalidSignatureError
from pathfinder.utils.types import ChannelId, Address


class BalanceProof(object):
    """
    TODO: adopt final balance proof format
    """
    def __init__(
        self,
        nonce: int,
        transferred_amount: int,
        channel_id: ChannelId,
        token_network_contract: Address,
        additional_hash: bytes,
        signature: bytes
    ):
        self.nonce = nonce
        self.transferred_amount = transferred_amount
        self.channel_id = channel_id
        self.token_network_contract = token_network_contract
        self.additional_hash = additional_hash
        self.signature = signature
        self._verify()

    def _verify(self):
        raise InvalidSignatureError()
