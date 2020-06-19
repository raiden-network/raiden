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

    def create_channel(self):
        self.channel = self.pc.createDataChannel(to_checksum_address(self.partner_address))


async def handle_event(ag_transceiver: AGTransceiver, peer_connections: Dict[Address, RTCPartner], event):
    log.debug("received event from transport", ag_event=event)
    event_data = event["data"]
    event_type = event["type"]
    partner_address = event["address"]

    if partner_address not in peer_connections:
        peer_connections[partner_address] = RTCPartner(partner_address, RTCPeerConnection(), None)
    rtc_partner = peer_connections[partner_address]

    if event_type == "create_channel":
        await create_channel(rtc_partner, ag_transceiver, partner_address)
    if event_type == "message":
        send_message(rtc_partner, event_data)
    if event_type == "set_remote_description":
        await set_remote_description(rtc_partner, ag_transceiver, event_data)


async def create_channel(rtc_partner: RTCPartner, ag_transceiver: AGTransceiver, partner_address: Address):
    pc = rtc_partner.pc
    rtc_partner.create_channel()

    offer = await pc.createOffer()
    await pc.setLocalDescription(offer)

    event = {"type": "local_description",
             "data": {
                 "sdp": pc.localDescription.sdp,
                 "type": pc.localDescription.type
             },
             "address": partner_address
             }

    await ag_transceiver.send_event_to_gevent(event)

    @rtc_partner.channel.on("message")
    async def on_message(message):
        await ag_transceiver.message_to_gevent_queue.aput(message)


async def set_remote_description(rtc_partner: RTCPartner, ag_transceiver: AGTransceiver, description):
    remote_description = RTCSessionDescription(description['sdp'], description['type'])
    sdp_type = description['type']
    pc = rtc_partner.pc
    await pc.setRemoteDescription(remote_description)

    @rtc_partner.pc.on("datachannel")
    def on_datachannel(channel):
        rtc_partner.channel = channel
        print(f"received channel {channel.label}")

        @channel.on("close")
        def channel_closed():
            rtc_partner.channel = None

        @channel.on("message")
        async def on_message(message):
            await ag_transceiver.message_to_gevent_queue.aput(message)

    if sdp_type == "offer":
        # send answer
        answer = await pc.createAnswer()
        await pc.setLocalDescription(answer)
        event = {"type": "local_description",
                 "data": {
                     "sdp": pc.localDescription.sdp,
                     "type": pc.localDescription.type
                 },
                 "address": rtc_partner.partner_address
                 }

        await ag_transceiver.send_event_to_gevent(event)


def send_message(rtc_partner: RTCPartner, message):
    channel = rtc_partner.channel
    if channel is not None and channel.readyState == "open":
        channel.send(message)


async def run_aiortc(transceiver: AGTransceiver):

    peer_connections = transceiver.peer_connections

    while True:
        event = await transceiver.aget_event()
        await handle_event(transceiver, peer_connections, event)


def aio_loop(ag_transceiver) -> None:
    loop = asyncio.get_event_loop()
    try:
        asyncio.ensure_future(run_aiortc(ag_transceiver))
        if not loop.is_running():
            loop.run_forever()
    except KeyboardInterrupt:
        loop.close()
