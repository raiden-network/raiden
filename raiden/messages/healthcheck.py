from dataclasses import dataclass

from raiden.messages.abstract import SignedMessage
from raiden.messages.cmdid import CmdId
from raiden.utils.signing import pack_data
from raiden.utils.typing import ClassVar, Nonce, RaidenProtocolVersion


@dataclass(repr=False, eq=False)
class Ping(SignedMessage):
    """ Healthcheck message.

    This message is sent to another node with an unique nonce, a Pong response is
    expected. If the recipient takes too long to send a Pong back it is assumed
    the node is offline.

    If the transport requires, this message can also be used to keep a
    connection alive and preserve NAT mappings.
    """

    cmdid: ClassVar[CmdId] = CmdId.PING

    nonce: Nonce
    current_protocol_version: RaidenProtocolVersion

    def _data_to_sign(self) -> bytes:
        return pack_data(
            (self.cmdid.value, "uint8"),
            (b"\x00" * 3, "bytes"),  # padding
            (self.nonce, "uint64"),
            (self.current_protocol_version, "uint8"),
        )


@dataclass(repr=False, eq=False)
class Pong(SignedMessage):
    """ Response to a Ping message. """

    cmdid: ClassVar[CmdId] = CmdId.PONG

    nonce: Nonce

    def _data_to_sign(self) -> bytes:
        return pack_data(
            (self.cmdid.value, "uint8"), (b"\x00" * 3, "bytes"), (self.nonce, "uint64")
        )
