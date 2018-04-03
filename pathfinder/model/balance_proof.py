from eth_utils import is_checksum_address
from raiden_libs.utils import private_key_to_address

from pathfinder.utils.exceptions import InvalidAddressChecksumError
from pathfinder.utils.types import Address, ChannelId


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
        signature: bytes = None,
        private_key: str = None,
    ):
        self.nonce = nonce
        self.transferred_amount = transferred_amount
        self.locksroot = locksroot
        self.channel_id = channel_id
        self.token_network_address = token_network_address
        self.chain_id = chain_id
        self.additional_hash = additional_hash

        if signature is None:
            assert private_key is not None, 'Private key required to create valid balance proof.'
            self.signature = self._sign(private_key)
        else:
            self.signature = signature
        self.sender = self._recover_sender()

        if not is_checksum_address(token_network_address):
            raise InvalidAddressChecksumError(
                'Missing or invalid checksum on token network address.'
            )

    def _recover_sender(self) -> Address:
        # FIXME: use actual ECRecover magic here
        return Address(self.signature.decode())

    def _sign(self, private_key: str) -> bytes:
        # FIXME: this is not how to signature
        return private_key_to_address(private_key).encode()
