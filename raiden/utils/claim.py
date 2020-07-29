import json
from itertools import islice
from pathlib import Path
from typing import Any, Dict, Generator, Iterable, Optional, Tuple

import click
from eth_utils import to_canonical_address
from structlog import get_logger

from raiden.constants import BLOCK_ID_LATEST
from raiden.settings import MediationFeeConfig
from raiden.storage.serialization import DictSerializer
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
    ContractReceiveChannelWithdraw,
    ContractReceiveRouteNew,
)
from raiden.utils.formatting import to_checksum_address
from raiden.utils.signer import Signer
from raiden.utils.typing import (
    Address,
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

log = get_logger(__name__)


DEFAULT_SETTLE_TIMEOUT = BlockTimeout(100)
DEFAULT_TOKEN_AMOUNT = TokenAmount(100)


_DUMMY_ADDRESS = to_canonical_address("0x" + "0" * 40)

EMPTY_CLAIM = Claim(
    chain_id=ChainID(2 ** 256 - 1),
    token_network_address=TokenNetworkAddress(_DUMMY_ADDRESS),
    owner=Address(_DUMMY_ADDRESS),
    partner=Address(_DUMMY_ADDRESS),
    total_amount=TokenAmount(0),
)
EMPTY_CLAIM.signature = Signature(b"")


def parse_claims_file(
    claims_path: Path,
) -> Tuple[Optional[Dict[str, Any]], Optional[Generator[Claim, None, None]]]:
    if not claims_path.exists():
        return None, None

    def iterate_claims() -> Generator[Claim, None, None]:
        # TODO: add error handling
        with claims_path.open("rt") as claims_file:
            for line in claims_file:
                claim = json.loads(line.strip())
                if "operator" in claim:
                    # First line contains the operator info, skip
                    continue
                yield DictSerializer.deserialize({"_type": "raiden.transfer.state.Claim", **claim})

    with claims_path.open("rt") as claims_file:
        for line in claims_file:
            operator_info = json.loads(line.strip())
            msg = "Invalid claims file. First line must be operator info"
            assert "operator" in operator_info, msg
            break
    return operator_info, iterate_claims()


def get_state_changes_for_claims(
    chain_state: ChainState,
    claims: Iterable[Claim],
    node_address: Address,
    token_network_registry_address: TokenNetworkRegistryAddress,
    settle_timeout: BlockTimeout,
    reveal_timeout: BlockTimeout,
    fee_config: MediationFeeConfig,
    proxy_manager: Any,  # FIXME: remove import cycle
    ignore_unrelated: bool = True,
) -> List[StateChange]:
    from raiden.transfer import views

    state_changes: List[StateChange] = []

    for claim in claims:

        token_network_state = views.get_token_network_by_address(
            chain_state=chain_state, token_network_address=claim.token_network_address
        )
        if token_network_state is None:
            continue

        # If node is channel participant, create NettingChannelState
        if node_address == claim.owner or node_address == claim.partner:
            token_network_proxy = proxy_manager.token_network(
                token_network_state.address, BLOCK_ID_LATEST
            )
            details = token_network_proxy._detail_participant(
                claim.channel_id, claim.owner, claim.partner, BLOCK_ID_LATEST
            )

            our_state = NettingChannelEndState(
                address=claim.owner if claim.owner == node_address else claim.partner,
            )
            partner_state = NettingChannelEndState(
                address=claim.partner if claim.owner == node_address else claim.owner,
            )

            channel_state = NettingChannelState(
                canonical_identifier=CanonicalIdentifier(
                    chain_identifier=claim.chain_id,
                    token_network_address=claim.token_network_address,
                    channel_identifier=claim.channel_id,
                ),
                token_address=token_network_state.token_address,
                token_network_registry_address=token_network_registry_address,
                reveal_timeout=reveal_timeout,
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

            state_changes.extend(
                [
                    ContractReceiveChannelNew(
                        channel_state=channel_state,
                        transaction_hash=TransactionHash(b""),
                        block_number=BlockNumber(0),
                        block_hash=BlockHash(b""),
                    ),
                    # Fake the deposit with the claims value
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
                            claim=claim,
                        ),
                        transaction_hash=TransactionHash(b""),
                        block_number=BlockNumber(1),
                        block_hash=BlockHash(b""),
                        fee_config=MediationFeeConfig(),
                    ),
                    # Fake the already withdrawn amount
                    ContractReceiveChannelWithdraw(
                        canonical_identifier=CanonicalIdentifier(
                            chain_identifier=claim.chain_id,
                            token_network_address=claim.token_network_address,
                            channel_identifier=claim.channel_id,
                        ),
                        participant=claim.owner,
                        total_withdraw=details.withdrawn,
                        transaction_hash=TransactionHash(b""),
                        block_number=BlockNumber(1),
                        block_hash=BlockHash(b""),
                        fee_config=MediationFeeConfig(),
                    ),
                ]
            )

        # Node is not a participant, just store routing information
        # No need to add a deposit state change here
        elif not ignore_unrelated:
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


def create_hub_jsonl(
    operator_signer: Signer,
    token_network_address: TokenNetworkAddress,
    chain_id: ChainID,
    hub_address: Address,
    addresses: List[Address],
    output_file: Path,
    token_amount: TokenAmount = DEFAULT_TOKEN_AMOUNT,
    num_direct_channels: int = 0,
) -> None:
    with output_file.open("wt") as output_fd:
        output_fd.write(
            json.dumps(
                dict(
                    operator=to_checksum_address(operator_signer.address),
                    hub=to_checksum_address(hub_address),
                )
            )
        )
        output_fd.write("\n")

        claims = create_hub_claims(
            operator_signer=operator_signer,
            token_network_address=token_network_address,
            chain_id=chain_id,
            hub_address=hub_address,
            num_direct_channels=num_direct_channels,
            addresses=addresses,
            token_amount=token_amount,
        )
        with click.progressbar(
            claims, label="Generating claims", length=len(addresses) * 2
        ) as progress_claims:
            for claim in progress_claims:
                serialized_claim = json.dumps(claim.serialize())
                output_fd.write(serialized_claim + "\n")


def create_hub_claims(
    operator_signer: Signer,
    token_network_address: TokenNetworkAddress,
    chain_id: ChainID,
    hub_address: Address,
    addresses: List[Address],
    token_amount: TokenAmount = DEFAULT_TOKEN_AMOUNT,
    num_direct_channels: int = 0,
) -> Generator[Claim, None, None]:
    channels = []

    # Open direct channels for node pairs, i.e. (0, 1), (1, 2), (2, 3)
    # Nodes still are connected to the hub
    for partner1, partner2 in islice(zip(addresses, addresses[1:]), num_direct_channels):
        channels.append((partner1, partner2, token_amount))
        channels.append((partner2, partner1, token_amount))

    for address in addresses:
        channels.append((address, hub_address, token_amount))
        channels.append((hub_address, address, token_amount))

    yield from generate_claims(operator_signer, token_network_address, chain_id, channels)


def generate_claims(
    operator_signer: Signer,
    token_network_address: TokenNetworkAddress,
    chain_id: ChainID,
    channels: List[Tuple[Address, Address, TokenAmount]],
) -> Generator[Claim, None, None]:
    for p1, p2, amount in channels:
        yield generate_claim(
            operator_signer=operator_signer,
            chain_id=chain_id,
            token_network_address=token_network_address,
            address=p1,
            partner=p2,
            amount=amount,
        )


def generate_claim(
    operator_signer: Signer,
    token_network_address: TokenNetworkAddress,
    chain_id: ChainID,
    address: Address,
    partner: Address,
    amount: TokenAmount,
) -> Claim:
    claim = Claim(
        chain_id=chain_id,
        token_network_address=token_network_address,
        owner=address,
        partner=partner,
        total_amount=amount,
    )
    claim.sign(operator_signer)
    return claim


class ClaimGenerator:
    """ Class for iteratively adding claims, can be used in test fixtures, etc... """

    def __init__(self, operator_signer: Signer, chain_id: ChainID, hub_address: Optional[Address]):
        self.operator_signer = operator_signer
        self.chain_id = chain_id
        self.hub_address = hub_address
        self.tokennetworkaddress_claims: Dict[TokenNetworkAddress, List[Claim]] = dict()

    def add_claim(
        self,
        amount: TokenAmount,
        address: Address,
        partner: Optional[Address],
        token_network_address: TokenNetworkAddress,
    ) -> Claim:
        """ Adds a claim between `address` and `partner` (or hub if `None`).
        Returns the newly generated claim.
        """
        if partner is None:
            partner = self.hub_address
        if partner is None:
            raise ValueError("No partner, and no hub_address, can not generate claim")
        if token_network_address not in self.tokennetworkaddress_claims:
            self.tokennetworkaddress_claims[token_network_address] = list()
        claim = generate_claim(
            operator_signer=self.operator_signer,
            chain_id=self.chain_id,
            address=address,
            partner=partner,
            amount=amount,
            token_network_address=token_network_address,
        )
        self.tokennetworkaddress_claims[token_network_address].append(claim)
        return claim

    def add_2_claims(
        self,
        amounts: Tuple[TokenAmount, TokenAmount],
        address: Address,
        partner: Optional[Address],
        token_network_address: TokenNetworkAddress,
    ) -> List[Claim]:
        """ Adds bi-directional claims for `address` and `partner` (or hub if `None`).
        Returns the newly generated claims.
        """
        if partner is None:
            partner = self.hub_address
        if partner is None:
            raise ValueError("No partner, and no hub_address, can not generate claim")
        claims = [
            self.add_claim(
                address=address,
                partner=partner,
                amount=amounts[0],
                token_network_address=token_network_address,
            ),
            self.add_claim(
                address=partner,
                partner=address,
                amount=amounts[1],
                token_network_address=token_network_address,
            ),
        ]
        return claims

    def claims(self) -> List[Claim]:
        claims = []
        for token_network_address in self.tokennetworkaddress_claims.keys():
            for claim in self.tokennetworkaddress_claims[token_network_address]:
                claims.append(claim)
        return sorted(claims)
