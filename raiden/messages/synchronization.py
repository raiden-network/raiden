from dataclasses import dataclass

from raiden.constants import EMPTY_SIGNATURE
from raiden.messages.abstract import SignedMessage, SignedRetrieableMessage
from raiden.messages.cmdid import CmdId
from raiden.utils.signing import pack_data
from raiden.utils.typing import ClassVar, MessageID


@dataclass(repr=False, eq=False)
class Processed(SignedRetrieableMessage):
    """ Used by the recipient when a message which has to be validated against
    blockchain data was successfully processed.

    This message is only used to confirm the processing of messages which have
    some blockchain related data, where receiving the message is not
    sufficient. Consider the following scenario:

    - Node A starts a deposit of 5 tokens.
    - Node A sees the deposit, and starts a transfer.
    - Node B receives the the transfer, however it has not seen the deposit,
      therefore the transfer is rejected.

    Second scenario:

    - Node A has a lock which has expired, and sends the RemoveExpiredLock
      message.
    - Node B receives the message, but from its perspective the block at which
      the lock expires has not been confirmed yet, meaning that a reorg is
      possible and the secret can be registered on-chain.

    For both scenarios A has to keep retrying until B accepts the message.

    Notes:
        - This message is required even if the transport guarantees durability
          of the data.
        - This message provides a stronger guarantee then a Delivered,
          therefore it can replace it.
    """

    # FIXME: Processed should _not_ be SignedRetrieableMessage, but only SignedMessage
    cmdid: ClassVar[CmdId] = CmdId.PROCESSED

    message_identifier: MessageID

    @classmethod
    def from_event(cls, event):
        return cls(message_identifier=event.message_identifier, signature=EMPTY_SIGNATURE)

    def _data_to_sign(self) -> bytes:
        return pack_data(
            (self.cmdid.value, "uint8"),
            (b"\x00" * 3, "bytes"),  # padding
            (self.message_identifier, "uint64"),
        )


@dataclass(repr=False, eq=False)
class Delivered(SignedMessage):
    """ Informs the sender that the message was received *and* persisted.

    Notes:
        - This message provides a weaker guarantee in respect to the Processed
          message. It can be emulated by a transport layer that guarantess
          persistance, or it can be sent by the recipient before the received
          message is processed (threfore it does not matter if the message was
          successfully processed or not).
    """

    cmdid: ClassVar[CmdId] = CmdId.DELIVERED

    delivered_message_identifier: MessageID

    def _data_to_sign(self) -> bytes:
        return pack_data(
            (self.cmdid.value, "uint8"),
            (b"\x00" * 3, "bytes"),  # padding
            (self.delivered_message_identifier, "uint64"),
        )
