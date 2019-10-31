from raiden.messages.abstract import Message
from raiden.messages.synchronization import Processed
from raiden.messages.transfers import (
    LockedTransfer,
    LockExpired,
    RefundTransfer,
    RevealSecret,
    SecretRequest,
    Unlock,
)
from raiden.messages.withdraw import WithdrawConfirmation, WithdrawExpired, WithdrawRequest
from raiden.transfer.architecture import SendMessageEvent
from raiden.transfer.events import (
    SendProcessed,
    SendWithdrawConfirmation,
    SendWithdrawExpired,
    SendWithdrawRequest,
)
from raiden.transfer.mediated_transfer.events import (
    SendBalanceProof,
    SendLockedTransfer,
    SendLockExpired,
    SendRefundTransfer,
    SendSecretRequest,
    SendSecretReveal,
)
from raiden.utils.typing import MYPY_ANNOTATION


def message_from_sendevent(send_event: SendMessageEvent) -> Message:
    if type(send_event) == SendLockedTransfer:
        assert isinstance(send_event, SendLockedTransfer), MYPY_ANNOTATION
        return LockedTransfer.from_event(send_event)
    elif type(send_event) == SendSecretReveal:
        assert isinstance(send_event, SendSecretReveal), MYPY_ANNOTATION
        return RevealSecret.from_event(send_event)
    elif type(send_event) == SendBalanceProof:
        assert isinstance(send_event, SendBalanceProof), MYPY_ANNOTATION
        return Unlock.from_event(send_event)
    elif type(send_event) == SendSecretRequest:
        assert isinstance(send_event, SendSecretRequest), MYPY_ANNOTATION
        return SecretRequest.from_event(send_event)
    elif type(send_event) == SendRefundTransfer:
        assert isinstance(send_event, SendRefundTransfer), MYPY_ANNOTATION
        return RefundTransfer.from_event(send_event)
    elif type(send_event) == SendLockExpired:
        assert isinstance(send_event, SendLockExpired), MYPY_ANNOTATION
        return LockExpired.from_event(send_event)
    elif type(send_event) == SendWithdrawRequest:
        assert isinstance(send_event, SendWithdrawRequest), MYPY_ANNOTATION
        return WithdrawRequest.from_event(send_event)
    elif type(send_event) == SendWithdrawConfirmation:
        assert isinstance(send_event, SendWithdrawConfirmation), MYPY_ANNOTATION
        return WithdrawConfirmation.from_event(send_event)
    elif type(send_event) == SendWithdrawExpired:
        assert isinstance(send_event, SendWithdrawExpired), MYPY_ANNOTATION
        return WithdrawExpired.from_event(send_event)
    elif type(send_event) == SendProcessed:
        assert isinstance(send_event, SendProcessed), MYPY_ANNOTATION
        return Processed.from_event(send_event)
    else:
        raise ValueError(f"Unknown event type {send_event}")
