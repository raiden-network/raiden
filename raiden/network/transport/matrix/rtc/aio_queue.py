from asyncio import Future
from dataclasses import dataclass

import gevent
from aiortc import RTCDataChannel, RTCPeerConnection
from gevent.lock import Semaphore

from raiden.network.transport.matrix.rtc import aiogevent
from raiden.network.transport.matrix.utils import my_place_or_yours
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import Address, Any, Callable, Optional


def make_wrapped_greenlet(target: Callable, *args: Any, **kwargs: Any) -> Future:
    glet = gevent.Greenlet(target, *args, **kwargs)
    wrapped_glet = aiogevent.wrap_greenlet(glet)
    glet.start()
    return wrapped_glet


@dataclass
class RTCPartner:
    partner_address: Address
    pc: RTCPeerConnection
    channel: Optional[RTCDataChannel] = None

    def create_channel(self, node_address: Address) -> None:
        lower_address = my_place_or_yours(node_address, self.partner_address)
        higher_address = self.partner_address if lower_address == node_address else node_address
        channel_name = (
            f"{to_checksum_address(lower_address)}|{to_checksum_address(higher_address)}"
        )
        self.channel = self.pc.createDataChannel(channel_name)


class AGLock:
    def __init__(self) -> None:
        self.lock = Semaphore()

    async def __aenter__(self) -> None:
        await make_wrapped_greenlet(self.lock.acquire)

    async def __aexit__(self, _1: Any, _2: Any, _3: Any) -> None:
        await make_wrapped_greenlet(self.lock.release)

    def __enter__(self) -> None:
        self.lock.acquire()

    def __exit__(self, _1: Any, _2: Any, _3: Any) -> None:
        self.lock.release()
