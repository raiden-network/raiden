import asyncio
import time

import gevent
import structlog
from aiortc import RTCDataChannel, RTCPeerConnection, RTCSessionDescription
from gevent import Greenlet

from raiden.network.transport.matrix.rtc.aio_queue import RTCPartner
from raiden.network.transport.matrix.rtc.aiogevent import yield_future
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import Address, Any, Callable, Coroutine, Dict, Optional

log = structlog.get_logger(__name__)


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


async def create_channel(
    peer_connections: Dict[Address, RTCPartner],
    partner_address: Address,
    node_address: Address,
    handle_message_callback: Callable,
) -> RTCSessionDescription:

    if partner_address not in peer_connections:
        peer_connections[partner_address] = RTCPartner(partner_address, RTCPeerConnection(), None)

    rtc_partner = peer_connections[partner_address]
    pc = rtc_partner.pc
    rtc_partner.create_channel(node_address)

    offer = await pc.createOffer()
    await pc.setLocalDescription(offer)

    msg = "Channel must be created already"
    assert rtc_partner.channel is not None, msg

    @rtc_partner.channel.on("message")
    async def on_message(message: Dict[str, bytes]) -> None:
        log.debug(
            "Received message in aio kingdom",
            node=to_checksum_address(node_address),
            message=message,
            time=time.time(),
        )
        handle_message_callback({"type": "message", "data": message, "address": partner_address})

    return pc.localDescription


async def set_remote_description(
    rtc_partner: RTCPartner,
    description: Dict[str, str],
    node_address: Address,
    handle_message_callback: Callable,
) -> Optional[RTCSessionDescription]:

    remote_description = RTCSessionDescription(description["sdp"], description["type"])
    sdp_type = description["type"]
    pc = rtc_partner.pc
    await pc.setRemoteDescription(remote_description)

    @rtc_partner.pc.on("datachannel")
    def on_datachannel(channel: RTCDataChannel) -> None:  # pylint: disable=unused-variable
        rtc_partner.channel = channel
        log.debug(f"received channel {channel.label}", node=to_checksum_address(node_address))

        @channel.on("close")
        def channel_closed() -> None:  # pylint: disable=unused-variable
            rtc_partner.channel = None

        @channel.on("message")
        async def on_message(message: Dict[str, bytes]) -> None:  # pylint:disable=unused-variable
            log.debug(
                "Received message in aio kingdom",
                node=to_checksum_address(node_address),
                message=message,
                time=time.time(),
            )
            handle_message_callback(message)

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
            "sending message in aio kingdom",
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


def stop_rtc(peer_connections: Dict[Address, RTCPartner], node_address: Address) -> None:

    log.debug("Gracefully closing RTC channels", node=to_checksum_address(node_address))

    for rtc_partner in peer_connections.values():
        if rtc_partner.channel:
            rtc_partner.channel.close()
