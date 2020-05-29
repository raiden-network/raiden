from dataclasses import dataclass, replace

from hypothesis.strategies import builds, composite, integers, sampled_from

from raiden.messages.decode import lockedtransfersigned_from_message
from raiden.messages.encode import message_from_sendevent
from raiden.messages.transfers import LockedTransfer
from raiden.tests.utils import factories
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.mediated_transfer.events import (
    SendLockedTransfer,
    SendSecretRequest,
    SendSecretReveal,
    SendUnlock,
)
from raiden.transfer.mediated_transfer.initiator import send_lockedtransfer
from raiden.transfer.mediated_transfer.state import (
    LockedTransferSignedState,
    TransferDescriptionWithSecretState,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ActionInitTarget,
    ReceiveSecretRequest,
    ReceiveSecretReveal,
)
from raiden.transfer.state import HopState, NettingChannelState, RouteState
from raiden.transfer.state_change import ReceiveUnlock
from raiden.utils.signer import LocalSigner
from raiden.utils.typing import (
    MYPY_ANNOTATION,
    Address,
    Any,
    BlockNumber,
    List,
    MessageID,
    PrivateKey,
)


def signed_transfer_from_description(
    private_key: PrivateKey,
    description: TransferDescriptionWithSecretState,
    channel: NettingChannelState,
    message_id: MessageID,
    block_number: BlockNumber,
    route_state: RouteState,
    route_states: List[RouteState],
) -> LockedTransferSignedState:
    send_locked_transfer = send_lockedtransfer(
        transfer_description=description,
        channel_state=channel,
        message_identifier=message_id,
        block_number=block_number,
        route_state=route_state,
        route_states=route_states,
    )
    message = message_from_sendevent(send_locked_transfer)
    assert isinstance(message, LockedTransfer), MYPY_ANNOTATION
    message.sign(LocalSigner(private_key))
    return lockedtransfersigned_from_message(message)


def action_init_initiator_to_action_init_target(
    action: ActionInitInitiator,
    channel: NettingChannelState,
    block_number: BlockNumber,
    route_state: RouteState,
    address: Address,
    private_key: PrivateKey,
) -> ActionInitTarget:
    transfer = signed_transfer_from_description(
        private_key=private_key,
        description=action.transfer,
        channel=channel,
        message_id=factories.make_message_identifier(),
        block_number=block_number,
        route_state=route_state,
        route_states=action.routes,
    )
    from_hop = HopState(node_address=address, channel_identifier=channel.identifier)
    return ActionInitTarget(
        from_hop=from_hop, transfer=transfer, sender=address, balance_proof=transfer.balance_proof
    )


@dataclass(frozen=True)
class SendSecretRequestInNode:
    event: SendSecretRequest
    node: Address


def send_secret_request_to_receive_secret_request(
    source: SendSecretRequestInNode,
) -> ReceiveSecretRequest:
    return ReceiveSecretRequest(
        sender=source.node,
        payment_identifier=source.event.payment_identifier,
        amount=source.event.amount,
        expiration=source.event.expiration,
        secrethash=source.event.secrethash,
    )


@dataclass(frozen=True)
class SendSecretRevealInNode:
    event: SendSecretReveal
    node: Address


def send_secret_reveal_to_recieve_secret_reveal(
    source: SendSecretRevealInNode,
) -> ReceiveSecretReveal:
    return ReceiveSecretReveal(
        sender=source.node, secrethash=source.event.secrethash, secret=source.event.secret
    )


@dataclass(frozen=True)
class SendLockedTransferInNode:
    event: SendLockedTransfer
    action: ActionInitInitiator
    node: Address
    private_key: PrivateKey


def send_lockedtransfer_to_locked_transfer(source: SendLockedTransferInNode) -> LockedTransfer:
    locked_transfer = message_from_sendevent(source.event)
    assert isinstance(locked_transfer, LockedTransfer), MYPY_ANNOTATION
    locked_transfer.sign(LocalSigner(source.private_key))
    return locked_transfer


def locked_transfer_to_action_init_target(locked_transfer: LockedTransfer) -> ActionInitTarget:
    from_transfer = lockedtransfersigned_from_message(locked_transfer)
    channel_id = from_transfer.balance_proof.channel_identifier  # pylint: disable=no-member
    from_hop = HopState(
        node_address=Address(locked_transfer.initiator), channel_identifier=channel_id
    )
    init_target_statechange = ActionInitTarget(
        from_hop=from_hop,
        transfer=from_transfer,
        balance_proof=from_transfer.balance_proof,
        sender=from_transfer.balance_proof.sender,  # pylint: disable=no-member
    )

    return init_target_statechange


@dataclass(frozen=True)
class SendUnlockInNode:
    event: SendUnlock
    node: Address
    private_key: PrivateKey


def send_unlock_to_receive_unlock(
    source: SendUnlockInNode, canonical_identifier: CanonicalIdentifier
) -> ReceiveUnlock:
    mirrored_balance_proof = replace(
        source.event.balance_proof, canonical_identifier=canonical_identifier
    )
    signed_balance_proof = factories.make_signed_balance_proof_from_unsigned(
        unsigned=mirrored_balance_proof, signer=LocalSigner(source.private_key)
    )
    return ReceiveUnlock(
        sender=source.node,
        message_identifier=source.event.message_identifier,
        secret=source.event.secret,
        secrethash=source.event.secrethash,
        balance_proof=signed_balance_proof,
    )


@dataclass
class Scrambling:
    field: str
    value: Any

    @property
    def kwargs(self):
        return {self.field: self.value}


@composite
def scrambling(draw, fields):
    field = draw(sampled_from(list(fields.keys())))
    value = draw(fields[field])
    return Scrambling(field, value)


@composite
def balance_proof_scrambling(draw):
    fields = {
        "nonce": builds(factories.make_nonce),
        "transferred_amount": integers(min_value=0),
        "locked_amount": integers(min_value=0),
        "locksroot": builds(factories.make_locksroot),
        "canonical_identifier": builds(factories.make_canonical_identifier),
        "balance_hash": builds(factories.make_transaction_hash),
    }
    return draw(scrambling(fields))  # pylint: disable=no-value-for-parameter


@composite
def hash_time_lock_scrambling(draw):
    fields = {
        "amount": integers(min_value=0),
        "expiration": integers(min_value=1),
        "secrethash": builds(factories.make_secret_hash),
    }
    return draw(scrambling(fields))  # pylint: disable=no-value-for-parameter


@composite
def locked_transfer_scrambling(draw):
    fields = {
        "token": builds(factories.make_token_address),
        "token_network_address": builds(factories.make_token_network_address),
        "channel_identifier": builds(factories.make_channel_identifier),
        "chain_id": builds(factories.make_chain_id),
    }
    return draw(scrambling(fields))  # pylint: disable=no-value-for-parameter
