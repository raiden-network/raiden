from typing import Union

import structlog
from eth_utils import to_checksum_address

from raiden import constants
from raiden.messages import RequestMonitoring, UpdatePFS
from raiden.settings import MONITORING_MIN_CAPACITY, MONITORING_REWARD
from raiden.transfer import channel, views
from raiden.transfer.architecture import BalanceProofSignedState, BalanceProofUnsignedState
from raiden.transfer.state import ChainState, NettingChannelState
from raiden.utils import to_rdn
from raiden.utils.typing import TYPE_CHECKING, Address

if TYPE_CHECKING:
    from raiden.raiden_service import RaidenService


log = structlog.get_logger(__name__)


def update_services_from_balance_proof(
    raiden: "RaidenService",
    chain_state: ChainState,
    balance_proof: Union[BalanceProofSignedState, BalanceProofUnsignedState],
) -> None:
    update_path_finding_service_from_balance_proof(
        raiden=raiden, chain_state=chain_state, new_balance_proof=balance_proof
    )
    if isinstance(balance_proof, BalanceProofSignedState):
        update_monitoring_service_from_balance_proof(
            raiden=raiden,
            chain_state=chain_state,
            new_balance_proof=balance_proof,
            monitoring_service_contract_address=raiden.default_msc_address,
        )


def update_path_finding_service_from_channel_state(
    raiden: "RaidenService", channel_state: NettingChannelState
):
    msg = UpdatePFS.from_channel_state(channel_state)
    msg.sign(raiden.signer)
    raiden.transport.send_global(constants.PATH_FINDING_BROADCASTING_ROOM, msg)
    log.debug("Sent a PFS Update", message=msg, channel_state=channel_state)


def update_path_finding_service_from_balance_proof(
    raiden: "RaidenService",
    chain_state: ChainState,
    new_balance_proof: Union[BalanceProofSignedState, BalanceProofUnsignedState],
) -> None:
    channel_state = views.get_channelstate_by_canonical_identifier(
        chain_state=chain_state, canonical_identifier=new_balance_proof.canonical_identifier
    )
    network_address = new_balance_proof.canonical_identifier.token_network_address
    error_msg = (
        f"tried to send a balance proof in non-existant channel "
        f"token_network_address: {to_checksum_address(network_address)} "
    )
    assert channel_state is not None, error_msg
    update_path_finding_service_from_channel_state(raiden=raiden, channel_state=channel_state)


def update_monitoring_service_from_balance_proof(
    raiden: "RaidenService",
    chain_state: ChainState,
    new_balance_proof: BalanceProofSignedState,
    monitoring_service_contract_address: Address,
) -> None:
    if raiden.config["services"]["monitoring_enabled"] is False:
        return

    channel_state = views.get_channelstate_by_canonical_identifier(
        chain_state=chain_state, canonical_identifier=new_balance_proof.canonical_identifier
    )

    msg = (
        f"Failed to update monitoring service due to inability to find "
        f"channel: {new_balance_proof.channel_identifier} "
        f"token_network_address: {to_checksum_address(new_balance_proof.token_network_address)}."
    )
    assert channel_state, msg

    balance = channel.get_balance(
        sender=channel_state.our_state, receiver=channel_state.partner_state
    )

    if balance < MONITORING_MIN_CAPACITY:
        log.warn(
            f"Skipping update to Monitoring service. "
            f"Available balance of {balance} is less than configured "
            f"minimum capacity of {MONITORING_MIN_CAPACITY}"
        )
        return

    assert raiden.user_deposit is not None
    rei_balance = raiden.user_deposit.effective_balance(raiden.address, "latest")
    if rei_balance < MONITORING_REWARD:
        rdn_balance = to_rdn(rei_balance)
        rdn_reward = to_rdn(MONITORING_REWARD)
        log.warn(
            f"Skipping update to Monitoring service. "
            f"Your deposit balance {rdn_balance} is less than "
            f"the required monitoring service reward of {rdn_reward}"
        )
        return

    log.info(
        "Received new balance proof, creating message for Monitoring Service.",
        balance_proof=new_balance_proof,
    )

    monitoring_message = RequestMonitoring.from_balance_proof_signed_state(
        new_balance_proof, MONITORING_REWARD, monitoring_service_contract_address
    )
    monitoring_message.sign(raiden.signer)
    raiden.transport.send_global(constants.MONITORING_BROADCASTING_ROOM, monitoring_message)
