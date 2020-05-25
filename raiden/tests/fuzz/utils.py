from raiden.messages.decode import lockedtransfersigned_from_message
from raiden.messages.encode import message_from_sendevent
from raiden.messages.transfers import LockedTransfer
from raiden.transfer.mediated_transfer.initiator import send_lockedtransfer
from raiden.transfer.mediated_transfer.state import (
    LockedTransferSignedState,
    TransferDescriptionWithSecretState,
)
from raiden.transfer.state import NettingChannelState, RouteState
from raiden.utils.signer import LocalSigner
from raiden.utils.typing import MYPY_ANNOTATION, Address, BlockNumber, List, MessageID, PrivateKey


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
