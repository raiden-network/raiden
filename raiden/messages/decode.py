from raiden.messages.transfers import EnvelopeMessage, LockedTransferBase
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.mediated_transfer.state import LockedTransferSignedState
from raiden.transfer.state import BalanceProofSignedState, HashTimeLockState
from raiden.utils.typing import AdditionalHash


def balanceproof_from_envelope(envelope_message: EnvelopeMessage) -> BalanceProofSignedState:
    assert envelope_message.sender, "envelope_message must be signed"
    return BalanceProofSignedState(
        nonce=envelope_message.nonce,
        transferred_amount=envelope_message.transferred_amount,
        locked_amount=envelope_message.locked_amount,
        locksroot=envelope_message.locksroot,
        message_hash=AdditionalHash(envelope_message.message_hash),
        signature=envelope_message.signature,
        sender=envelope_message.sender,
        canonical_identifier=CanonicalIdentifier(
            chain_identifier=envelope_message.chain_id,
            token_network_address=envelope_message.token_network_address,
            channel_identifier=envelope_message.channel_identifier,
        ),
    )


def lockedtransfersigned_from_message(message: LockedTransferBase) -> LockedTransferSignedState:
    """ Create LockedTransferSignedState from a LockedTransfer message. """
    balance_proof = balanceproof_from_envelope(message)

    lock = HashTimeLockState(message.lock.amount, message.lock.expiration, message.lock.secrethash)
    transfer_state = LockedTransferSignedState(
        message_identifier=message.message_identifier,
        payment_identifier=message.payment_identifier,
        token=message.token,
        balance_proof=balance_proof,
        lock=lock,
        initiator=message.initiator,
        target=message.target,
        routes=[r.route for r in message.metadata.routes],
    )

    return transfer_state
