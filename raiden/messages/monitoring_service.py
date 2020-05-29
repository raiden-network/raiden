from dataclasses import dataclass, field

from raiden.constants import EMPTY_SIGNATURE
from raiden.messages.abstract import SignedMessage
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.state import BalanceProofSignedState
from raiden.transfer.utils import hash_balance_data
from raiden.utils.packing import pack_balance_proof, pack_reward_proof, pack_signed_balance_proof
from raiden.utils.signer import Signer, recover
from raiden.utils.typing import (
    AdditionalHash,
    Address,
    BalanceHash,
    ChainID,
    ChannelID,
    MonitoringServiceAddress,
    Nonce,
    Optional,
    Signature,
    TokenAmount,
    TokenNetworkAddress,
    typecheck,
)
from raiden_contracts.constants import MessageTypeId


@dataclass(repr=False, eq=False)
class SignedBlindedBalanceProof:
    """Message sub-field `onchain_balance_proof` for `RequestMonitoring`.
    """

    channel_identifier: ChannelID
    token_network_address: TokenNetworkAddress
    nonce: Nonce
    additional_hash: AdditionalHash
    chain_id: ChainID
    balance_hash: BalanceHash
    signature: Signature
    non_closing_signature: Optional[Signature] = field(default=EMPTY_SIGNATURE)

    def __post_init__(self) -> None:
        if self.signature == EMPTY_SIGNATURE:
            raise ValueError("balance proof is not signed")

    @classmethod
    def from_balance_proof_signed_state(
        cls, balance_proof: BalanceProofSignedState
    ) -> "SignedBlindedBalanceProof":
        typecheck(balance_proof, BalanceProofSignedState)

        # pylint: disable=unexpected-keyword-arg
        return cls(
            channel_identifier=balance_proof.channel_identifier,
            token_network_address=balance_proof.token_network_address,
            nonce=balance_proof.nonce,
            additional_hash=balance_proof.message_hash,
            chain_id=balance_proof.chain_id,
            signature=balance_proof.signature,
            balance_hash=hash_balance_data(
                balance_proof.transferred_amount,
                balance_proof.locked_amount,
                balance_proof.locksroot,
            ),
        )

    def _data_to_sign(self) -> bytes:
        packed = pack_signed_balance_proof(
            msg_type=MessageTypeId.BALANCE_PROOF_UPDATE,
            nonce=self.nonce,
            balance_hash=self.balance_hash,
            additional_hash=self.additional_hash,
            canonical_identifier=CanonicalIdentifier(
                chain_identifier=self.chain_id,
                token_network_address=self.token_network_address,
                channel_identifier=self.channel_identifier,
            ),
            partner_signature=self.signature,
        )
        return packed

    def _sign(self, signer: Signer) -> Signature:
        """Internal function for the overall `sign` function of `RequestMonitoring`.
        """
        # Important: we don't write the signature to `.signature`
        data = self._data_to_sign()
        return signer.sign(data)


@dataclass(repr=False, eq=False)
class RequestMonitoring(SignedMessage):
    """Message to request channel watching from a monitoring service.

    Spec:
        https://raiden-network-specification.readthedocs.io/en/latest/monitoring_service.html\
        #monitor-request
    """

    balance_proof: SignedBlindedBalanceProof
    reward_amount: TokenAmount
    monitoring_service_contract_address: MonitoringServiceAddress
    non_closing_participant: Address
    non_closing_signature: Optional[Signature] = None

    def __post_init__(self) -> None:
        typecheck(self.balance_proof, SignedBlindedBalanceProof)

    def __hash__(self) -> int:
        return hash((self._data_to_sign(), self.signature, self.non_closing_signature))

    @classmethod
    def from_balance_proof_signed_state(
        cls,
        balance_proof: BalanceProofSignedState,
        non_closing_participant: Address,
        reward_amount: TokenAmount,
        monitoring_service_contract_address: MonitoringServiceAddress,
    ) -> "RequestMonitoring":
        typecheck(balance_proof, BalanceProofSignedState)

        onchain_balance_proof = SignedBlindedBalanceProof.from_balance_proof_signed_state(
            balance_proof=balance_proof
        )
        # pylint: disable=unexpected-keyword-arg
        return cls(
            balance_proof=onchain_balance_proof,
            reward_amount=reward_amount,
            signature=EMPTY_SIGNATURE,
            non_closing_participant=non_closing_participant,
            monitoring_service_contract_address=monitoring_service_contract_address,
        )

    @property
    def reward_proof_signature(self) -> Optional[Signature]:
        return self.signature

    def _data_to_sign(self) -> bytes:
        """ Return the binary data to be/which was signed """
        assert self.non_closing_signature is not None, "Message is not signed yet."
        packed = pack_reward_proof(
            chain_id=self.balance_proof.chain_id,
            token_network_address=self.balance_proof.token_network_address,
            reward_amount=self.reward_amount,
            monitoring_service_contract_address=self.monitoring_service_contract_address,
            non_closing_participant=self.non_closing_participant,
            non_closing_signature=self.non_closing_signature,
        )
        return packed

    def sign(self, signer: Signer) -> None:
        """This method signs twice:
            - the `non_closing_signature` for the balance proof update
            - the `reward_proof_signature` for the monitoring request
        """
        self.non_closing_signature = self.balance_proof._sign(signer)
        message_data = self._data_to_sign()
        self.signature = signer.sign(data=message_data)

    def verify_request_monitoring(
        self, partner_address: Address, requesting_address: Address
    ) -> bool:
        """ One should only use this method to verify integrity and signatures of a
        RequestMonitoring message. """
        if not self.non_closing_signature:
            return False

        balance_proof_data = pack_balance_proof(
            nonce=self.balance_proof.nonce,
            balance_hash=self.balance_proof.balance_hash,
            additional_hash=self.balance_proof.additional_hash,
            canonical_identifier=CanonicalIdentifier(
                chain_identifier=self.balance_proof.chain_id,
                token_network_address=self.balance_proof.token_network_address,
                channel_identifier=self.balance_proof.channel_identifier,
            ),
        )
        blinded_data = pack_signed_balance_proof(
            msg_type=MessageTypeId.BALANCE_PROOF_UPDATE,
            nonce=self.balance_proof.nonce,
            balance_hash=self.balance_proof.balance_hash,
            additional_hash=self.balance_proof.additional_hash,
            canonical_identifier=CanonicalIdentifier(
                chain_identifier=self.balance_proof.chain_id,
                token_network_address=self.balance_proof.token_network_address,
                channel_identifier=self.balance_proof.channel_identifier,
            ),
            partner_signature=self.balance_proof.signature,
        )
        reward_proof_data = pack_reward_proof(
            chain_id=self.balance_proof.chain_id,
            token_network_address=self.balance_proof.token_network_address,
            reward_amount=self.reward_amount,
            monitoring_service_contract_address=self.monitoring_service_contract_address,
            non_closing_participant=requesting_address,
            non_closing_signature=self.non_closing_signature,
        )
        reward_proof_signature = self.reward_proof_signature or EMPTY_SIGNATURE
        return (
            recover(balance_proof_data, self.balance_proof.signature) == partner_address
            and recover(blinded_data, self.non_closing_signature) == requesting_address
            and recover(reward_proof_data, reward_proof_signature) == requesting_address
        )
