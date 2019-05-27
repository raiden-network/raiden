from dataclasses import dataclass

from eth_utils import to_bytes, to_checksum_address

from raiden import constants
from raiden.utils.typing import (
    Address,
    ChainID,
    ChannelID,
    T_Address,
    T_ChainID,
    T_ChannelID,
    TokenNetworkAddress,
)


@dataclass(frozen=True, order=True)
class CanonicalIdentifier:
    chain_identifier: ChainID
    token_network_address: TokenNetworkAddress
    channel_identifier: ChannelID

    def validate(self) -> None:
        if not isinstance(self.token_network_address, T_Address):
            raise ValueError("token_network_address must be an address instance")

        if not isinstance(self.channel_identifier, T_ChannelID):
            raise ValueError("channel_identifier must be an ChannelID instance")

        if not isinstance(self.chain_identifier, T_ChainID):
            raise ValueError("chain_id must be a ChainID instance")

        if self.channel_identifier < 0 or self.channel_identifier > constants.UINT256_MAX:
            raise ValueError("channel id is invalid")

    def __str__(self) -> str:
        return (
            f"{self.chain_identifier}|{to_checksum_address(self.token_network_address)}|"
            f"{self.channel_identifier}"
        )

    @staticmethod
    def from_string(string: str) -> "CanonicalIdentifier":
        try:
            chain_id_str, token_network_address_hex, channel_id_str = string.split("|")
            return CanonicalIdentifier(
                chain_identifier=ChainID(int(chain_id_str)),
                token_network_address=to_bytes(hexstr=token_network_address_hex),
                channel_identifier=ChannelID(int(channel_id_str)),
            )
        except ValueError:
            raise ValueError(f"Could not reconstruct canonical identifier from string: {string}")


@dataclass(frozen=True)
class QueueIdentifier:
    recipient: Address
    canonical_identifier: CanonicalIdentifier


# According to the smart contracts as of 07/08:
# https://github.com/raiden-network/raiden-contracts/blob/fff8646ebcf2c812f40891c2825e12ed03cc7628/raiden_contracts/contracts/TokenNetwork.sol#L213
# channel_identifier can never be 0. We make this a requirement in the client and use this fact
# to signify that a channel_identifier of `0` passed to the messages adds them to the
# global queue
CANONICAL_IDENTIFIER_GLOBAL_QUEUE = CanonicalIdentifier(
    ChainID(0), TokenNetworkAddress(b"\1" * 20), ChannelID(0)
)
