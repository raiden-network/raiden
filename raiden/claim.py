import json
from pathlib import Path

from eth_utils import to_canonical_address

from raiden.settings import MediationFeeConfig
from raiden.storage.serialization import DictSerializer
from raiden.transfer import views
from raiden.transfer.architecture import StateChange
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.mediated_transfer.mediation_fee import FeeScheduleState
from raiden.transfer.state import (
    ChainState,
    Claim,
    NettingChannelEndState,
    NettingChannelState,
    SuccessfulTransactionState,
    TransactionChannelDeposit,
)
from raiden.transfer.state_change import (
    ContractReceiveChannelDeposit,
    ContractReceiveChannelNew,
    ContractReceiveRouteNew,
)
from raiden.utils.typing import (
    Address,
    Balance,
    BlockHash,
    BlockNumber,
    BlockTimeout,
    List,
    Signature,
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
    TransactionHash,
)
from raiden_contracts.utils.type_aliases import ChainID, TokenAmount

CLAIM_FILE_PATH = Path("./claims.json")
DEFAULT_SETTLE_TIMEOUT = BlockTimeout(100)
DEFAULT_REVEAL_TIMEOUT = BlockTimeout(50)


_DUMMY_ADDRESS = to_canonical_address("0x" + "0" * 40)

EmptyClaim = Claim(
    chain_id=ChainID(2 ** 256 - 1),
    token_network_address=TokenNetworkAddress(_DUMMY_ADDRESS),
    owner=Address(_DUMMY_ADDRESS),
    partner=Address(_DUMMY_ADDRESS),
    total_amount=TokenAmount(0),
)
EmptyClaim.signature = Signature(b"")


def parse_claims_file() -> List[Claim]:
    if not CLAIM_FILE_PATH.exists():
        return []

    # TODO: add error handling
    claims_data = json.loads(CLAIM_FILE_PATH.read_text())
    return [
        DictSerializer.deserialize({"_type": "raiden.claim.Claim", **claim})
        for claim in claims_data["claims"]
    ]


def get_state_changes_for_claims(
    chain_state: ChainState,
    claims: List[Claim],
    node_address: Address,
    token_network_registry_address: TokenNetworkRegistryAddress,
    settle_timeout: BlockTimeout,
    fee_config: MediationFeeConfig,
) -> List[StateChange]:
    state_changes: List[StateChange] = []

    for claim in claims:

        token_network_state = views.get_token_network_by_address(
            chain_state=chain_state, token_network_address=claim.token_network_address
        )
        assert token_network_state is not None, "Token network does not exist"

        # If node is channel participant, create NettingChannelState
        if node_address == claim.owner or node_address == claim.partner:
            our_state = NettingChannelEndState(
                claim.owner if claim.owner == node_address else claim.partner, Balance(0)
            )
            partner_state = NettingChannelEndState(
                claim.partner if claim.owner == node_address else claim.owner, Balance(0)
            )

            channel_state = NettingChannelState(
                canonical_identifier=CanonicalIdentifier(
                    chain_identifier=claim.chain_id,
                    token_network_address=claim.token_network_address,
                    channel_identifier=claim.channel_id,
                ),
                token_address=token_network_state.token_address,
                token_network_registry_address=token_network_registry_address,
                reveal_timeout=DEFAULT_REVEAL_TIMEOUT,
                settle_timeout=settle_timeout,
                fee_schedule=FeeScheduleState(
                    cap_fees=fee_config.cap_meditation_fees,
                    flat=fee_config.get_flat_fee(token_network_state.token_address),
                    proportional=fee_config.get_proportional_fee(token_network_state.token_address)
                    # no need to set the imbalance fee here, will be set during deposit
                ),
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
            state_changes.append(
                ContractReceiveChannelDeposit(
                    canonical_identifier=CanonicalIdentifier(
                        chain_identifier=claim.chain_id,
                        token_network_address=claim.token_network_address,
                        channel_identifier=claim.channel_id,
                    ),
                    deposit_transaction=TransactionChannelDeposit(
                        participant_address=claim.owner,
                        contract_balance=claim.total_amount,
                        deposit_block_number=BlockNumber(1),
                    ),
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
                        channel_identifier=claim.channel_id,
                    ),
                    participant1=claim.owner,
                    participant2=claim.partner,
                )
            )

    return state_changes
