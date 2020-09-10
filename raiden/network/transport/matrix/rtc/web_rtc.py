import asyncio
import time
from dataclasses import dataclass

import gevent
import structlog
from aiortc import RTCDataChannel, RTCPeerConnection, RTCSessionDescription
from gevent import Greenlet

from raiden.network.transport.matrix.rtc.aiogevent import yield_future
from raiden.network.transport.matrix.utils import my_place_or_yours
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import Address, Any, Callable, Coroutine, Dict, List, Optional

log = structlog.get_logger(__name__)


@dataclass
class RTCPartner:
    partner_address: Address
    peer_connection: RTCPeerConnection
    channel: Optional[RTCDataChannel] = None

    def create_channel(self, node_address: Address) -> None:
        lower_address = my_place_or_yours(node_address, self.partner_address)
        higher_address = self.partner_address if lower_address == node_address else node_address
        channel_name = (
            f"{to_checksum_address(lower_address)}|{to_checksum_address(higher_address)}"
        )
        self.channel = self.peer_connection.createDataChannel(channel_name)


def spawn_coroutine(
    coroutine: Coroutine, callback: Callable, partner_address: Address
) -> Greenlet:

    return gevent.spawn(
        wait_for_future, asyncio.ensure_future(coroutine), callback, partner_address
    )


def wait_for_future(future: Any, callback: Callable, partner_address: Address) -> None:
    result = yield_future(future)
    if callback is not None:
        callback(result, partner_address)


class WebRTCManager:
    def __init__(
        self,
        node_address: Optional[Address],
        handle_message_callback: Callable[[str, Address], None],
        handle_sdp_callback: Callable[[Dict[str, Any], Address], None],
    ) -> None:
        self.node_address: Optional[Address] = node_address
        self._handle_message_callback = handle_message_callback
        self._handle_sdp_callback = handle_sdp_callback
        self.rtc_partners: Dict[Address, RTCPartner] = dict()
        self.coroutines: List[Coroutine] = list()

    def _get_rtc_partner(self, partner_address: Address) -> RTCPartner:
        if partner_address not in self.rtc_partners:
            self.rtc_partners[partner_address] = RTCPartner(partner_address, RTCPeerConnection())
        return self.rtc_partners[partner_address]

    def has_ready_channel(self, partner_address: Address) -> bool:
        if partner_address not in self.rtc_partners:
            return False
        channel = self.rtc_partners[partner_address].channel
        if channel is None:
            return False
        if channel.readyState == "open":
            return True
        return False

    def create_channel(self, partner_address: Address) -> None:
        assert self.node_address, "Transport is not started yet but tried to create rtc channel"

        rtc_partner = self._get_rtc_partner(partner_address)
        spawn_coroutine(
            coroutine=create_channel(
                rtc_partner, self.node_address, self._handle_message_callback,
            ),
            callback=self._handle_sdp_callback,
            partner_address=partner_address,
        )

    def set_remote_description(
        self, partner_address: Address, description: Dict[str, str]
    ) -> None:
        assert self.node_address, "Transport is not started yet but tried to set candidates"
        rtc_partner = self._get_rtc_partner(partner_address)
        spawn_coroutine(
            coroutine=set_remote_description(
                rtc_partner=rtc_partner,
                node_address=self.node_address,
                description=description,
                handle_message_callback=self._handle_message_callback,
            ),
            callback=self._handle_sdp_callback,
            partner_address=partner_address,
        )

    def stop(self) -> None:
        if self.node_address is None:
            return

        log.debug("Gracefully closing RTC channels", node=to_checksum_address(self.node_address))

        for rtc_partner in self.rtc_partners.values():
            if rtc_partner.channel:
                rtc_partner.channel.close()


async def create_channel(
    rtc_partner: RTCPartner, node_address: Address, handle_message_callback: Callable,
) -> RTCSessionDescription:

    pc = rtc_partner.peer_connection
    rtc_partner.create_channel(node_address)

    offer = await pc.createOffer()
    await pc.setLocalDescription(offer)

    msg = "Channel must be created already"
    assert rtc_partner.channel is not None, msg

    @rtc_partner.channel.on("message")
    async def on_message(message: Dict[str, bytes]) -> None:  # pylint: disable=unused-variable
        log.debug(
            "Received message in asyncio kingdom",
            node=to_checksum_address(node_address),
            message=message,
            time=time.time(),
        )
        handle_message_callback(message, rtc_partner.partner_address)

    return pc.localDescription


async def set_remote_description(
    rtc_partner: RTCPartner,
    node_address: Address,
    description: Dict[str, str],
    handle_message_callback: Callable,
) -> Optional[RTCSessionDescription]:

    remote_description = RTCSessionDescription(description["sdp"], description["type"])
    sdp_type = description["type"]
    pc = rtc_partner.peer_connection
    await pc.setRemoteDescription(remote_description)

    @rtc_partner.peer_connection.on("datachannel")
    def on_datachannel(channel: RTCDataChannel) -> None:  # pylint: disable=unused-variable
        rtc_partner.channel = channel
        log.debug(f"received channel {channel.label}", node=to_checksum_address(node_address))

        @channel.on("close")
        def channel_closed() -> None:  # pylint: disable=unused-variable
            rtc_partner.channel = None

        @channel.on("message")
        async def on_message(message: Dict[str, bytes]) -> None:  # pylint:disable=unused-variable
            log.debug(
                "Received message in asyncio kingdom",
                node=to_checksum_address(node_address),
                message=message,
                time=time.time(),
            )
            handle_message_callback(message, rtc_partner.partner_address)

    if sdp_type == "offer":
        # send answer
        answer = await pc.createAnswer()
        await pc.setLocalDescription(answer)

        return pc.localDescription
    return None


def send_message(rtc_partner: RTCPartner, message: str, node_address: Address) -> None:
    channel = rtc_partner.channel
    if channel is not None and channel.readyState == "open":
        log.debug(
            "sending message in asyncio kingdom",
            node=to_checksum_address(node_address),
            message=message,
            time=time.time(),
        )
        channel.send(message)
    else:
        log.debug(
            "Channel is not open. ReadyState: "
            f"{channel.readyState if channel is not None else 'No channel exists'}",
            node=to_checksum_address(node_address),
        )


# class AGLock:
#    def __init__(self) -> None:
#        self.lock = Semaphore()
#
#    async def __aenter__(self) -> None:
#        await make_wrapped_greenlet(self.lock.acquire)
#
#    async def __aexit__(self, _1: Any, _2: Any, _3: Any) -> None:
#        await make_wrapped_greenlet(self.lock.release)
#
#    def __enter__(self) -> None:
#        self.lock.acquire()
#
#    def __exit__(self, _1: Any, _2: Any, _3: Any) -> None:
#        self.lock.release()
