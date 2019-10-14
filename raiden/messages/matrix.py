from dataclasses import dataclass

from raiden.messages.abstract import SignedMessage
from raiden.messages.cmdid import CmdId
from raiden.utils.signing import pack_data
from raiden.utils.typing import ClassVar


@dataclass(repr=False, eq=False)
class ReachabilityNotification(SignedMessage):
    # FIXME Message needs a nonce/identifier to prevent replays/spoofing

    cmdid: ClassVar[CmdId] = CmdId.REACHABILITYNOTIFICATION
    address_reachability: int

    def _data_to_sign(self) -> bytes:
        return pack_data(
            (self.cmdid.value, "uint8"),
            (b"\x00" * 3, "bytes"),  # padding
            (self.address_reachability, "uint8"),
        )
