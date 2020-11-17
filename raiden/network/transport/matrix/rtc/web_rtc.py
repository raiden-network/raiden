import time
from dataclasses import dataclass, field
from functools import partial

import gevent
import structlog
from aiortc import RTCDataChannel, RTCPeerConnection, RTCSessionDescription
from aiortc.sdp import candidate_from_sdp
from gevent.event import Event

from raiden.constants import RTCChannelState, SDPTypes
from raiden.network.transport.matrix.rtc.utils import spawn_coroutine
from raiden.network.transport.matrix.utils import my_place_or_yours
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import (
    Address,
    Any,
    Callable,
    Coroutine,
    Dict,
    Optional,
    Sequence,
    Set,
    Union,
)

log = structlog.get_logger(__name__)


@dataclass
class RTCPartner:
    partner_address: Address
    peer_connection: RTCPeerConnection
    channel: Optional[RTCDataChannel] = field(default=None)
    partner_ready_event: Event = field(default_factory=Event)

    def create_channel(self, node_address: Address) -> None:
        lower_address = my_place_or_yours(node_address, self.partner_address)
        higher_address = self.partner_address if lower_address == node_address else node_address
        channel_name = (
            f"{to_checksum_address(lower_address)}|{to_checksum_address(higher_address)}"
        )
        self.channel = self.peer_connection.createDataChannel(channel_name)

    def get_call_id(self, node_address: Address) -> str:
        lower_address = my_place_or_yours(node_address, self.partner_address)
        higher_address = self.partner_address if lower_address == node_address else node_address
        call_id = f"{to_checksum_address(lower_address)}|{to_checksum_address(higher_address)}"
        return call_id


class WebRTCManager:
    def __init__(
        self,
        node_address: Optional[Address],
        handle_message_callback: Callable[[str, Address], None],
        handle_sdp_callback: Callable[[Optional[RTCSessionDescription], Address], None],
    ) -> None:
        self.node_address: Optional[Address] = node_address
        self._handle_message_callback = handle_message_callback
        self._handle_sdp_callback = handle_sdp_callback
        self.address_to_rtc_partners: Dict[Address, RTCPartner] = {}
        self.wrapped_coroutines: Set[gevent.Greenlet] = set()

    def get_rtc_partner(self, partner_address: Address) -> RTCPartner:
        if partner_address not in self.address_to_rtc_partners:
            self.address_to_rtc_partners[partner_address] = RTCPartner(
                partner_address, RTCPeerConnection()
            )
        return self.address_to_rtc_partners[partner_address]

    def has_ready_channel(self, partner_address: Address) -> bool:
        if partner_address not in self.address_to_rtc_partners:
            return False
        channel = self.address_to_rtc_partners[partner_address].channel
        if channel is None:
            return False
        if channel.readyState == RTCChannelState.OPEN.value:
            return True
        return False

    def _reset_state(self) -> None:
        self.address_to_rtc_partners = {}
        self.wrapped_coroutines = set()

    def _spawn_web_rtc_coroutine(
        self,
        coroutine: Coroutine,
        callback: Optional[Callable[[Any, Address], None]],
        partner_address: Address,
    ) -> None:
        self.wrapped_coroutines.add(
            spawn_coroutine(
                coroutine=coroutine, callback=callback, partner_address=partner_address
            )
        )

    def spawn_create_channel(self, partner_address: Address) -> None:
        assert self.node_address, "Transport is not started yet but tried to create rtc channel"
        rtc_partner = self.get_rtc_partner(partner_address)
        coroutine = create_channel_coroutine(
            rtc_partner, self.node_address, self._handle_message_callback
        )
        self._spawn_web_rtc_coroutine(coroutine, self._handle_sdp_callback, partner_address)

    def set_candidates(
        self, partner_address: Address, description: Dict[str, Union[str, Sequence[str]]]
    ) -> None:
        assert self.node_address, "Transport is not started yet but tried to set candidates"
        msg = "Tried to set candidates, but RTCPeerConnection does not exist"
        assert partner_address in self.address_to_rtc_partners, msg
        rtc_partner = self.get_rtc_partner(partner_address)
        # TODO: check if remoteDescription is necessary precondition
        msg = "Partner remote description is not set, but tried to set candidates"
        assert rtc_partner.peer_connection.remoteDescription is not None, msg

        connection: RTCPeerConnection = rtc_partner.peer_connection
        for candidate_str in description["candidates"]:

            candidate = candidate_from_sdp(candidate_str)
            candidate.sdpMid = "0"
            connection.addIceCandidate(candidate)

    def spawn_set_remote_description(
        self, partner_address: Address, description: Dict[str, str]
    ) -> None:
        assert self.node_address, "Transport is not started yet but tried to set candidates"
        rtc_partner = self.get_rtc_partner(partner_address)

        if rtc_partner.peer_connection.remoteDescription is not None:
            log.debug(
                "Remote description already set",
                node=to_checksum_address(self.node_address),
                partner_address=to_checksum_address(partner_address),
            )
            return
        coroutine = set_remote_description_coroutine(
            rtc_partner=rtc_partner,
            node_address=self.node_address,
            description=description,
            handle_message_callback=self._handle_message_callback,
        )
        self._spawn_web_rtc_coroutine(coroutine, self._handle_sdp_callback, partner_address)

    def close(self, partner_address: Address) -> None:
        rtc_partner = self.address_to_rtc_partners.pop(partner_address, None)

        if rtc_partner is not None:
            aiortc_channel_close_callback(rtc_partner)
            self._spawn_web_rtc_coroutine(
                coroutine=rtc_partner.peer_connection.close(),
                callback=None,
                partner_address=rtc_partner.partner_address,
            )

    def stop(self) -> None:
        if self.node_address is None:
            return

        log.debug("Closing rtc channels", node=to_checksum_address(self.node_address))

        for rtc_partner in self.address_to_rtc_partners.values():
            aiortc_channel_close_callback(rtc_partner)

        gevent.joinall(set(self.wrapped_coroutines), raise_error=True)
        self._reset_state()


def aiortc_channel_close_callback(rtc_partner: RTCPartner) -> None:
    """callback if channel is closed. It is part of a partial function"""
    if rtc_partner.channel is not None:
        # remove all listeners on channel to not receive events anymore
        rtc_partner.channel.remove_all_listeners()
        rtc_partner.channel.close()
        rtc_partner.channel = None


async def aiortc_channel_message_callback(
    rtc_partner: RTCPartner,
    node_address: Address,
    handle_message_callback: Callable[[str, Address], None],
    message: str,
) -> None:
    """callback if message is received. It is part of a partial function"""
    assert rtc_partner.channel, "channel not set but received message"
    log.debug(
        "Received message in asyncio kingdom",
        node=to_checksum_address(node_address),
        partner_address=to_checksum_address(rtc_partner.partner_address),
        channel=rtc_partner.channel.label,
        message=message,
        time=time.time(),
    )
    # callback to transport
    handle_message_callback(message, rtc_partner.partner_address)


async def create_channel_coroutine(
    rtc_partner: RTCPartner,
    node_address: Address,
    handle_message_callback: Callable[[str, Address], None],
) -> Optional[RTCSessionDescription]:
    """Coroutine to create channel. Setting up channel in aiortc"""

    pc = rtc_partner.peer_connection
    rtc_partner.create_channel(node_address)

    offer = await pc.createOffer()
    await pc.setLocalDescription(offer)
    if rtc_partner.channel is None:
        return None

    log.debug("Created offer", offer=offer)

    # channel callback on message signal
    rtc_partner.channel.on(
        "message",
        partial(
            aiortc_channel_message_callback, rtc_partner, node_address, handle_message_callback
        ),
    )
    # channel callback on close signal
    rtc_partner.channel.on("close", partial(aiortc_channel_close_callback, rtc_partner))

    return pc.localDescription


async def set_remote_description_coroutine(
    rtc_partner: RTCPartner,
    node_address: Address,
    description: Dict[str, str],
    handle_message_callback: Callable[[str, Address], None],
) -> Optional[RTCSessionDescription]:
    """Coroutine to set remote description. Sets remote description in aiortc"""
    log.debug(
        "Received signalling message from partner",
        node=to_checksum_address(node_address),
        partner=to_checksum_address(rtc_partner.partner_address),
        type=description["type"],
        description=description["sdp"],
    )

    remote_description = RTCSessionDescription(description["sdp"], description["type"])
    sdp_type = description["type"]
    pc = rtc_partner.peer_connection
    try:
        await pc.setRemoteDescription(remote_description)
    except ValueError:
        return None

    @rtc_partner.peer_connection.on("datachannel")
    def on_datachannel(channel: RTCDataChannel) -> None:  # pylint: disable=unused-variable
        rtc_partner.channel = channel
        log.debug(f"Received rtc channel {channel.label}", node=to_checksum_address(node_address))

        rtc_partner.channel.on(
            "message",
            partial(
                aiortc_channel_message_callback, rtc_partner, node_address, handle_message_callback
            ),
        )
        rtc_partner.channel.on("close", partial(aiortc_channel_close_callback, rtc_partner))

    if sdp_type == SDPTypes.OFFER.value:
        # send answer
        answer = await pc.createAnswer()
        await pc.setLocalDescription(answer)
        return pc.localDescription
    return None


def send_rtc_message(rtc_partner: RTCPartner, message: str, node_address: Address) -> None:
    """Sends message through aiortc. Not an async function. Output is written to buffer"""
    channel = rtc_partner.channel
    if channel is not None and channel.readyState == RTCChannelState.OPEN.value:
        log.debug(
            "Sending message in asyncio kingdom",
            node=to_checksum_address(node_address),
            partner_address=to_checksum_address(rtc_partner.partner_address),
            channel=channel.label,
            message=message,
            time=time.time(),
        )
        channel.send(message)
    else:
        log.debug(
            "Channel is not open but trying to send a message.",
            node=to_checksum_address(node_address),
            partner_address=to_checksum_address(rtc_partner.partner_address),
            ready_state=channel.readyState if channel is not None else "No channel exists",
        )
