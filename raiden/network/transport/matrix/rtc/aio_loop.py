import asyncio
from dataclasses import dataclass
from typing import Dict

import structlog
from aiortc import RTCDataChannel, RTCPeerConnection, RTCSessionDescription

from raiden.network.transport.matrix.rtc.aio_queue import AGTransceiver
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import Address

log = structlog.get_logger(__name__)


@dataclass
class RTCPartner:
    partner_address: Address
    pc: RTCPeerConnection
    channel: RTCDataChannel = None

    def create_channel(self) -> None:
        self.channel = self.pc.createDataChannel(to_checksum_address(self.partner_address))


async def handle_event(
    ag_transceiver: AGTransceiver, peer_connections: Dict[Address, RTCPartner], event, node_address
):
    log.debug(
        "received event from transport", ag_event=event, node=to_checksum_address(node_address)
    )
    event_data = event["data"]
    event_type = event["type"]
    partner_address = event["address"]

    if partner_address not in peer_connections:
        peer_connections[partner_address] = RTCPartner(partner_address, RTCPeerConnection(), None)
    rtc_partner = peer_connections[partner_address]

    if event_type == "create_channel":
        await create_channel(rtc_partner, ag_transceiver, partner_address, node_address)
    if event_type == "message":
        send_message(rtc_partner, event_data, node_address)
    if event_type == "set_remote_description":
        await set_remote_description(rtc_partner, ag_transceiver, event_data, node_address)


async def create_channel(
    rtc_partner: RTCPartner, ag_transceiver: AGTransceiver, partner_address: Address, node_address
):
    pc = rtc_partner.pc
    rtc_partner.create_channel()

    offer = await pc.createOffer()
    await pc.setLocalDescription(offer)

    event = {
        "type": "local_description",
        "data": {"sdp": pc.localDescription.sdp, "type": pc.localDescription.type},
        "address": partner_address,
    }

    await ag_transceiver.send_event_to_gevent(event)

    @rtc_partner.channel.on("message")
    async def on_message(message):
        log.debug(
            "Received message in aio kingdom",
            node=to_checksum_address(node_address),
            message=message,
        )
        await ag_transceiver.send_event_to_gevent(
            {"type": "message", "data": message, "address": partner_address}
        )


async def set_remote_description(
    rtc_partner: RTCPartner, ag_transceiver: AGTransceiver, description, node_address
):
    remote_description = RTCSessionDescription(description["sdp"], description["type"])
    sdp_type = description["type"]
    pc = rtc_partner.pc
    await pc.setRemoteDescription(remote_description)

    @rtc_partner.pc.on("datachannel")
    def on_datachannel(channel):
        rtc_partner.channel = channel
        log.debug(f"received channel {channel.label}", node=to_checksum_address(node_address))

        @channel.on("close")
        def channel_closed():
            rtc_partner.channel = None

        @channel.on("message")
        async def on_message(message):  # pylint:disable=unused-variable
            log.debug(
                "Received message in aio kingdom",
                node=to_checksum_address(node_address),
                message=message,
            )
            await ag_transceiver.send_event_to_gevent(
                {"type": "message", "data": message, "address": rtc_partner.partner_address}
            )

    if sdp_type == "offer":
        # send answer
        answer = await pc.createAnswer()
        await pc.setLocalDescription(answer)
        event = {
            "type": "local_description",
            "data": {"sdp": pc.localDescription.sdp, "type": pc.localDescription.type},
            "address": rtc_partner.partner_address,
        }

        await ag_transceiver.send_event_to_gevent(event)


def send_message(rtc_partner: RTCPartner, message, node_address):
    channel = rtc_partner.channel
    if channel is not None and channel.readyState == "open":
        channel.send(message)
    else:
        log.debug(
            f"Channel is not open. ReadyState: {channel.readyState}",
            node=to_checksum_address(node_address),
        )


async def run_aiortc(transceiver: AGTransceiver, node_address, stop_event):
    peer_connections = transceiver.peer_connections

    log.debug(
        "AIORTC started", node=to_checksum_address(node_address),
    )

    while not stop_event.is_set():
        event = await transceiver.aget_event()
        await handle_event(transceiver, peer_connections, event, node_address)

    log.debug(
        "AIORTC stopped", node=to_checksum_address(node_address),
    )
