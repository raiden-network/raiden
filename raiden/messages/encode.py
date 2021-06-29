from raiden.messages.abstract import Message
from raiden.messages.synchronization import Processed
from raiden.messages.transfers import (
    LockedTransfer,
    LockExpired,
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
    SendLockedTransfer,
    SendLockExpired,
    SendSecretRequest,
    SendSecretReveal,
    SendUnlock,
)


_EVENT_MAP = {
    SendLockExpired: LockExpired,
    SendLockedTransfer: LockedTransfer,
    SendProcessed: Processed,
    SendSecretRequest: SecretRequest,
    SendSecretReveal: RevealSecret,
    SendUnlock: Unlock,
    SendWithdrawConfirmation: WithdrawConfirmation,
    SendWithdrawExpired: WithdrawExpired,
    SendWithdrawRequest: WithdrawRequest,
}


def message_from_sendevent(send_event: SendMessageEvent) -> Message:
    t_event = type(send_event)
    EventClass = _EVENT_MAP.get(t_event)
    if EventClass is None:
        raise ValueError(f"Unknown event type {t_event}")
    return EventClass.from_event(send_event)  # type: ignore
