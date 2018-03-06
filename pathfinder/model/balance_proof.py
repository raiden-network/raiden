from eth_utils import is_checksum_address

from pathfinder.utils.exceptions import InvalidAddressChecksumError
from pathfinder.utils.types import ChannelId, Address


class BalanceProof:
    def __init__(
        self,
        nonce: int,
        transferred_amount: int,
        locksroot: bytes,
        channel_id: ChannelId,
        token_network_address: Address,
        chain_id: int,
        additional_hash: bytes,
        signature: bytes
    ):
        self.nonce = nonce
        self.transferred_amount = transferred_amount
        self.locksroot = locksroot
        self.channel_id = channel_id
        self.token_network_address = token_network_address
        self.chain_id = chain_id
        self.additional_hash = additional_hash
        self.signature = signature
        self.sender = self._recover_sender()

        if not is_checksum_address(token_network_address):
            raise InvalidAddressChecksumError(
                'Missing or invalid checksum on token network address.'
            )

    def _recover_sender(self) -> Address:
        # TODO: reconstruct balance proof message and ecrecover
        return None
