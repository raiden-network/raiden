from dataclasses import dataclass

from raiden.messages.abstract import SignedMessage
from raiden.messages.cmdid import CmdId
from raiden.utils.signing import pack_data
from raiden.utils.typing import ClassVar, MessageID


@dataclass(repr=False, eq=False)
class ToDevice(SignedMessage):
    """
    Message, which can be directly sent to all devices of a node known by matrix,
    no room required. Messages which are supposed to be sent via transport.sent_to_device must
    subclass.
    """

    cmdid: ClassVar[CmdId] = CmdId.TODEVICE

    message_identifier: MessageID

    def _data_to_sign(self) -> bytes:
        return pack_data(
            (self.cmdid.value, "uint8"),
            (b"\x00" * 3, "bytes"),  # padding
            (self.message_identifier, "uint64"),
        )
