import json
from dataclasses import dataclass
from pathlib import Path

from eth_abi import encode_single
from eth_utils import keccak, to_canonical_address, to_hex
from web3 import Web3

from raiden.settings import MediationFeeConfig
from raiden.storage.serialization import DictSerializer
from raiden.transfer.architecture import StateChange
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.mediated_transfer.mediation_fee import FeeScheduleState
from raiden.transfer.state import (
    NettingChannelEndState,
    NettingChannelState,
    SuccessfulTransactionState,
    TokenNetworkGraphState,
    TokenNetworkState,
    TransactionChannelDeposit,
)
from raiden.transfer.state_change import (
    ContractReceiveChannelDeposit,
    ContractReceiveChannelNew,
    ContractReceiveNewTokenNetwork,
    ContractReceiveRouteNew,
)
from raiden.utils.formatting import to_checksum_address, to_hex_address
from raiden.utils.signer import Signer
from raiden.utils.typing import (
    Address,
    Any,
    Balance,
    BlockHash,
    BlockNumber,
    BlockTimeout,
    Dict,
    List,
    Optional,
    TokenAddress,
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
    TransactionHash,
)
from raiden_contracts.utils.type_aliases import ChainID, ChannelID, Signature, TokenAmount

CLAIM_FILE_PATH = Path("./claims.json")
DEFAULT_SETTLE_TIMEOUT = BlockTimeout(100)
DEFAULT_REVEAL_TIMEOUT = BlockTimeout(50)
TOKEN_ADDRESS = TokenAddress(to_canonical_address("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"))


@dataclass
class Claim:
    chain_id: ChainID
    token_network_address: TokenNetworkAddress
    owner: Address
    partner: Address
    total_amount: TokenAmount
    signature: Optional[Signature] = None

    def pack(self) -> bytes:
        return (
            Web3.toBytes(hexstr=to_hex_address(self.token_network_address))
            + encode_single("uint256", self.chain_id)
            + Web3.toBytes(hexstr=to_hex_address(self.owner))
            + Web3.toBytes(hexstr=to_hex_address(self.partner))
            + encode_single("uint256", self.total_amount)
        )

    def sign(self, signer: Signer) -> None:
        self.signature = signer.sign(data=self.pack())

    def serialize(self) -> Dict[str, Any]:
        assert self.signature is not None, "Claim not signed yet"
        return dict(
            chain_id=self.chain_id,
            token_network_address=to_checksum_address(self.token_network_address),
            owner=to_checksum_address(self.owner),
            partner=to_checksum_address(self.partner),
            total_amount=self.total_amount,
            signature=to_hex(self.signature),
        )

    def channel_id(self) -> ChannelID:
        if self.owner < self.partner:
            hashed_id = keccak(
                encode_single("uint256", self.chain_id)
                + self.token_network_address
                + self.owner
                + self.partner
            )
        else:
            hashed_id = keccak(
                encode_single("uint256", self.chain_id)
                + self.token_network_address
                + self.partner
                + self.owner
            )
        return ChannelID(int.from_bytes(bytes=hashed_id, byteorder="big"))


def parse_claims_file() -> List[Claim]:
    if not CLAIM_FILE_PATH.exists():
        return []

    # TODO: add error handling
    claims_data = json.loads(CLAIM_FILE_PATH.read_text())
    return [
        DictSerializer.deserialize({"_type": "raiden.claim.Claim", **claim})
        for claim in claims_data["claims"]
    ]


def create_new_token_network_event(
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_network_address: TokenNetworkAddress,
) -> List[StateChange]:
    return [
        ContractReceiveNewTokenNetwork(
            token_network_registry_address=token_network_registry_address,
            token_network=TokenNetworkState(
                address=token_network_address,
                token_address=TOKEN_ADDRESS,
                network_graph=TokenNetworkGraphState(token_network_address),
            ),
            transaction_hash=TransactionHash(b""),
            block_number=BlockNumber(0),
            block_hash=BlockHash(b""),
        ),
    ]


def claims_to_blockchain_events(
    claims: List[Claim],
    node_address: Address,
    token_network_registry_address: TokenNetworkRegistryAddress,
) -> List[StateChange]:
    state_changes = create_new_token_network_event(
        token_network_registry_address, claims[0].token_network_address
    )

    # TODO: check claim signature
    for claim in claims:
        # If node is channel participant, create NettingChannelState
        if node_address == claim.owner or node_address == claim.partner:
            our_state = NettingChannelEndState(
                claim.owner if claim.owner == node_address else claim.partner, Balance(0),
            )
            partner_state = NettingChannelEndState(
                claim.partner if claim.owner == node_address else claim.owner, Balance(0),
            )

            channel_state = NettingChannelState(
                canonical_identifier=CanonicalIdentifier(
                    chain_identifier=claim.chain_id,
                    token_network_address=claim.token_network_address,
                    channel_identifier=claim.channel_id(),
                ),
                token_address=TOKEN_ADDRESS,
                token_network_registry_address=token_network_registry_address,
                reveal_timeout=DEFAULT_REVEAL_TIMEOUT,
                settle_timeout=DEFAULT_SETTLE_TIMEOUT,
                fee_schedule=FeeScheduleState(),
                our_state=our_state,
                partner_state=partner_state,
                open_transaction=SuccessfulTransactionState(BlockNumber(0)),
                close_transaction=None,
                settle_transaction=None,
            )

            state_changes.append(
                ContractReceiveChannelNew(
                    channel_state=channel_state,
                    transaction_hash=TransactionHash(b""),
                    block_number=BlockNumber(0),
                    block_hash=BlockHash(b""),
                )
            )
            transaction_channel_deposit = TransactionChannelDeposit(
                participant_address=claim.owner,
                contract_balance=claim.total_amount,
                deposit_block_number=BlockNumber(1),
            )

            state_changes.append(
                ContractReceiveChannelDeposit(
                    canonical_identifier=CanonicalIdentifier(
                        chain_identifier=claim.chain_id,
                        token_network_address=claim.token_network_address,
                        channel_identifier=claim.channel_id(),
                    ),
                    deposit_transaction=transaction_channel_deposit,
                    transaction_hash=TransactionHash(b""),
                    block_number=BlockNumber(1),
                    block_hash=BlockHash(b""),
                    fee_config=MediationFeeConfig(),
                )
            )

        # Node is not a participant, just store routing information
        # No need to add a deposit state change here
        else:
            state_changes.append(
                ContractReceiveRouteNew(
                    transaction_hash=TransactionHash(b""),
                    block_number=BlockNumber(1),
                    block_hash=BlockHash(b""),
                    canonical_identifier=CanonicalIdentifier(
                        chain_identifier=claim.chain_id,
                        token_network_address=claim.token_network_address,
                        channel_identifier=claim.channel_id(),
                    ),
                    participant1=claim.owner,
                    participant2=claim.partner,
                )
            )

    return state_changes


def get_state_changes_for_claims(
    node_address: Address, token_network_registry_address: TokenNetworkRegistryAddress
) -> List[StateChange]:
    claims = parse_claims_file()
    return claims_to_blockchain_events(claims, node_address, token_network_registry_address)
