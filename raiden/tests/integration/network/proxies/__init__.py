from eth_utils import decode_hex, encode_hex
from web3 import Web3

from raiden.constants import LOCKSROOT_OF_NO_LOCKS, UINT256_MAX
from raiden.utils.signing import pack_data
from raiden.utils.typing import Address, ChannelID
from raiden_contracts.constants import MessageTypeId

LOCKSROOT_OF_NO_LOCKS_AS_STRING = encode_hex(LOCKSROOT_OF_NO_LOCKS)


class BalanceProof:
    """ A Balance Proof

    If transferred_amount, locked_amount and locksroot are set, balance_proof hash is
    computed using these values. Otherwise a value stored in _balance_hash is returned.

    Serialization will also add these items only if each of transferred_amount, locked_amount
    and locksroot is set.
    """

    def __init__(
        self,
        channel_identifier: ChannelID,
        token_network_address: Address,
        balance_hash: str = None,
        nonce: int = 0,
        additional_hash: str = "0x%064x" % 0,
        chain_id: int = 1,
        signature: str = None,
        transferred_amount: int = None,
        locked_amount: int = 0,
        locksroot: str = LOCKSROOT_OF_NO_LOCKS_AS_STRING,
    ):
        self.channel_identifier = channel_identifier
        self.token_network_address = token_network_address

        self._balance_hash = balance_hash
        self.additional_hash = additional_hash
        self.nonce = nonce
        self.chain_id = chain_id
        self.signature = signature

        if transferred_amount and locked_amount and locksroot and balance_hash:
            assert 0 <= transferred_amount <= UINT256_MAX
            assert 0 <= locked_amount <= UINT256_MAX
            assert (
                self.hash_balance_data(transferred_amount, locked_amount, locksroot)
                == balance_hash
            )

        self.transferred_amount = transferred_amount
        self.locked_amount = locked_amount
        self.locksroot = locksroot

    def serialize_bin(self, msg_type: MessageTypeId = MessageTypeId.BALANCE_PROOF):
        return pack_data(
            (self.token_network_address, "address"),
            (self.chain_id, "uint256"),
            (msg_type.value, "uint256"),
            (self.channel_identifier, "uint256"),
            (decode_hex(self.balance_hash), "bytes32"),
            (self.nonce, "uint256"),
            (decode_hex(self.additional_hash), "bytes32"),
        )

    @property
    def balance_hash(self) -> str:
        if self._balance_hash:
            return self._balance_hash
        if None not in (self.transferred_amount, self.locked_amount, self.locksroot):
            assert isinstance(self.transferred_amount, int)
            return encode_hex(
                self.hash_balance_data(self.transferred_amount, self.locked_amount, self.locksroot)
            )
        raise ValueError("Can't compute balance hash")

    @balance_hash.setter
    def balance_hash(self, value) -> None:
        self._balance_hash = value

    @staticmethod
    def hash_balance_data(transferred_amount: int, locked_amount: int, locksroot: str) -> str:
        return Web3.soliditySha3(  # pylint: disable=no-value-for-parameter
            ["uint256", "uint256", "bytes32"], [transferred_amount, locked_amount, locksroot]
        )
