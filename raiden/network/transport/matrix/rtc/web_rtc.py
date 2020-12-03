import asyncio
import time
from asyncio import Task
from functools import partial

import structlog
from aiortc import InvalidStateError, RTCDataChannel, RTCPeerConnection, RTCSessionDescription
from aiortc.sdp import candidate_from_sdp, candidate_to_sdp
from gevent.event import Event

from raiden.constants import (
    SDP_MID_DEFAULT,
    SDP_MLINE_INDEX_DEFAULT,
    RTCChannelState,
    RTCSignallingState,
    SDPTypes,
)
from raiden.network.transport.matrix.rtc.aiogevent import yield_future
from raiden.network.transport.matrix.rtc.utils import create_task_callback, wrap_callback
from raiden.network.transport.matrix.utils import my_place_or_yours
from raiden.utils.formatting import to_checksum_address
from raiden.utils.typing import Address, Any, Callable, Coroutine, Dict, List, Optional, Union

log = structlog.get_logger(__name__)


class CoroutineHandler:
    def __init__(self) -> None:
        self.coroutines: List[Task] = list()

    def schedule_task(
        self,
        coroutine: Coroutine,
        callback: Callable[[Any, Any], None] = None,
        *args: Any,
        **kwargs: Any,
    ) -> Task:

        task = asyncio.create_task(coroutine)
        if callback is not None:
            task_callback = create_task_callback(callback, *args, **kwargs)
            task.add_done_callback(task_callback)

        self.coroutines.append(task)
        return task

    async def wait_for_coroutines(self) -> None:
        log.debug("Waiting for coroutines", coroutines=self.coroutines)
        await asyncio.gather(*self.coroutines)

    def join_all_coroutines(self) -> None:
        yield_future(self.wait_for_coroutines())


class RTCPartner(CoroutineHandler):
    def __init__(self, partner_address: Address, peer_connection: RTCPeerConnection) -> None:
        super().__init__()
        self.partner_address = partner_address
        self.peer_connection = peer_connection
        self.channel: Optional[RTCDataChannel] = None
        self.partner_ready_event = Event()

    def _setup_channel(self, node_address: Address) -> None:
        lower_address = my_place_or_yours(node_address, self.partner_address)
        higher_address = self.partner_address if lower_address == node_address else node_address
        channel_name = (
            f"{to_checksum_address(lower_address)}|{to_checksum_address(higher_address)}"
        )
        self.channel = self.peer_connection.createDataChannel(channel_name)

    def _set_channel_callbacks(
        self, node_address: Address, handle_message_callback: Callable[[str, Address], None]
    ) -> None:
        if self.channel is None:
            return

        # channel callback on message signal
        self.channel.on(
            "message",
            partial(
                on_channel_message,
                self,
                node_address,
                handle_message_callback,
            ),
        )
        # channel callback on close signal
        self.channel.on("close", partial(on_channel_close, self))

    def get_call_id(self, node_address: Address) -> str:
        lower_address = my_place_or_yours(node_address, self.partner_address)
        higher_address = self.partner_address if lower_address == node_address else node_address
        call_id = f"{to_checksum_address(lower_address)}|{to_checksum_address(higher_address)}"
        return call_id

    async def _set_local_description(self, description: RTCSessionDescription) -> None:
        try:
            await self.peer_connection.setLocalDescription(description)
        except InvalidStateError:
            # this can happen if peer connection gets closed while awaiting in the try block
            return None

    async def initialize_signalling(
        self,
        node_address: Address,
        handle_message_callback: Callable[[str, Address], None],
    ) -> Optional[RTCSessionDescription]:
        """Coroutine to create channel. Setting up channel in aiortc"""

        self._setup_channel(node_address)
        offer = await self.peer_connection.createOffer()

        self.schedule_task(self._set_local_description(offer))

        if self.channel is None:
            return None

        self._set_channel_callbacks(node_address, handle_message_callback)
        log.debug("Created offer", offer=offer)

        return offer

    async def process_signalling(
        self,
        node_address: Address,
        description: Dict[str, str],
        handle_message_callback: Callable[[str, Address], None],
    ) -> Optional[RTCSessionDescription]:
        """Coroutine to set remote description. Sets remote description in aiortc"""
        log.debug(
            "Received signalling message from partner",
            node=to_checksum_address(node_address),
            partner_address=to_checksum_address(self.partner_address),
            type=description["type"],
            description=description["sdp"],
        )

        if self.peer_connection.signalingState == RTCSignallingState.CLOSED:
            log.debug(
                "Connection already closed",
                node_address=to_checksum_address(node_address),
                partner_address=to_checksum_address(self.partner_address),
            )
            return None

        remote_description = RTCSessionDescription(description["sdp"], description["type"])
        sdp_type = description["type"]
        # We need to wait for
        log.debug("Wait for existing tasks", coroutines=self.coroutines)
        await asyncio.gather(*self.coroutines)
        log.debug("Set Remote Description", description=description)
        await self.peer_connection.setRemoteDescription(remote_description)

        @self.peer_connection.on("datachannel")
        def on_datachannel(channel: RTCDataChannel) -> None:  # pylint: disable=unused-variable
            self.channel = channel
            log.debug(
                f"Received rtc channel {channel.label}", node=to_checksum_address(node_address)
            )

            self._set_channel_callbacks(node_address, handle_message_callback)

        if sdp_type == SDPTypes.OFFER.value:
            answer = await self.peer_connection.createAnswer()
            self.schedule_task(
                self._set_local_description(answer),
                callback=None,
            )
            return answer

        return None

    def send_message(self, message: str, node_address: Address) -> None:
        """Sends message through aiortc. Not an async function. Output is written to buffer"""

        if self.channel is not None and self.channel.readyState == RTCChannelState.OPEN.value:
            log.debug(
                "Sending message in asyncio kingdom",
                node=to_checksum_address(node_address),
                partner_address=to_checksum_address(self.partner_address),
                channel=self.channel.label,
                message=message,
                time=time.time(),
            )
            self.channel.send(message)
        else:
            log.debug(
                "Channel is not open but trying to send a message.",
                node=to_checksum_address(node_address),
                partner_address=to_checksum_address(self.partner_address),
                ready_state=self.channel.readyState
                if self.channel is not None
                else "No channel exists",
            )

    def close(self) -> Task:
        on_channel_close(self)
        return self.schedule_task(
            coroutine=self.peer_connection.close(),
            callback=None,
        )


class WebRTCManager(CoroutineHandler):
    def __init__(
        self,
        node_address: Optional[Address],
        _handle_message_callback: Callable[[str, Address], None],
        _handle_sdp_callback: Callable[[Optional[RTCSessionDescription], Address], None],
        _handle_candidates_callback: Callable[[List[Dict[str, Union[int, str]]], Address], None],
    ) -> None:
        super().__init__()
        self.node_address = node_address
        self._handle_message_callback = _handle_message_callback
        self._handle_sdp_callback = _handle_sdp_callback
        self._handle_candidates_callback = _handle_candidates_callback
        self.address_to_rtc_partners: Dict[Address, RTCPartner] = {}

    def get_rtc_partner(self, partner_address: Address) -> RTCPartner:
        if partner_address not in self.address_to_rtc_partners:

            self.address_to_rtc_partners[partner_address] = rtc_partner = RTCPartner(
                partner_address, RTCPeerConnection()
            )
            peer_connection = rtc_partner.peer_connection
            peer_connection.on(
                "icegatheringstatechange",
                partial(
                    on_ice_gathering_state_change,
                    rtc_partner=rtc_partner,
                    node_address=self.node_address,
                    candidates_callback=self._handle_candidates_callback,
                ),
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

    def initialize_signalling_for_address(self, partner_address: Address) -> None:
        assert self.node_address, "Transport is not started yet but tried to initialize signalling"
        rtc_partner = self.get_rtc_partner(partner_address)
        coroutine = rtc_partner.initialize_signalling(
            self.node_address,
            self._handle_message_callback,
        )

        self.schedule_task(coroutine, self._handle_sdp_callback, partner_address)

    def set_candidates_for_address(
        self, partner_address: Address, content: Dict[str, Any]
    ) -> None:
        assert self.node_address, "Transport is not started yet but tried to set candidates"
        rtc_partner = self.get_rtc_partner(partner_address)

        connection: RTCPeerConnection = rtc_partner.peer_connection

        if rtc_partner.peer_connection.sctp is None:
            # FIXME: we need to check if there are race conditions between
            #  remote descriptions (offer) not being set yet but already
            #  processing candidates which have been sent later
            #  If so a return must be replaced by a wait on the set_remote_description coroutine
            log.warning(
                "Received candidates before answer",
                node=to_checksum_address(self.node_address),
                partner_address=to_checksum_address(partner_address),
            )
            return

        for candidate in content["candidates"]:

            rtc_ice_candidate = candidate_from_sdp(candidate["candidate"])
            rtc_ice_candidate.sdpMid = candidate["sdpMid"]
            rtc_ice_candidate.sdpMLineIndex = candidate["sdpMLineIndex"]

            if rtc_ice_candidate.sdpMid != rtc_partner.peer_connection.sctp.mid:
                log.debug(
                    "Invalid candidate. Wrong sdpMid",
                    node_address=to_checksum_address(self.node_address),
                    candidate=candidate,
                    sctp_sdp_mid=rtc_partner.peer_connection.sctp.mid,
                )
                continue
            connection.addIceCandidate(rtc_ice_candidate)

    def process_signalling_for_address(
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

        self.schedule_task(
            coroutine=rtc_partner.process_signalling(
                node_address=self.node_address,
                description=description,
                handle_message_callback=self._handle_message_callback,
            ),
            callback=self._handle_sdp_callback,
            partner_address=partner_address,
        )

    def close_connection(self, partner_address: Address) -> Optional[Task]:
        msg = "Transport not yet started"
        assert self.node_address, msg

        log.debug(
            "Closing web rtc connection",
            node=to_checksum_address(self.node_address),
            partner_address=to_checksum_address(partner_address),
        )

        rtc_partner = self.address_to_rtc_partners.get(partner_address, None)

        if rtc_partner is not None:
            self.address_to_rtc_partners.pop(rtc_partner.partner_address, None)
            return rtc_partner.close()

        return None

    def stop(self) -> None:
        msg = "Transport not yet started"
        assert self.node_address, msg

        log.debug("Closing rtc connections", node=to_checksum_address(self.node_address))

        for partner_address in list(self.address_to_rtc_partners.keys()):
            rtc_partner = self.address_to_rtc_partners[partner_address]
            self.close_connection(partner_address)
            rtc_partner.join_all_coroutines()

        self.join_all_coroutines()
        self._reset_state()


def on_channel_close(rtc_partner: RTCPartner) -> None:
    """callback if channel is closed. It is part of a partial function"""
    if rtc_partner.channel is not None:
        # remove all listeners on channel to not receive events anymore
        rtc_partner.channel.remove_all_listeners()
        rtc_partner.channel.close()
        rtc_partner.channel = None


def on_channel_message(
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

    wrap_callback(
        handle_message_callback, message_data=message, partner_address=rtc_partner.partner_address
    )


def on_ice_gathering_state_change(
    rtc_partner: RTCPartner,
    node_address: Address,
    candidates_callback: Callable[[List[Dict[str, Union[int, str]]], Address], None],
) -> None:
    peer_connection = rtc_partner.peer_connection
    log.debug(
        "ICE gathering state changed",
        partner_address=to_checksum_address(rtc_partner.partner_address),
        node=to_checksum_address(node_address),
        state=peer_connection.iceGatheringState,
    )

    if peer_connection.iceGatheringState == "complete":
        # candidates are ready
        rtc_ice_candidates = (
            peer_connection.sctp.transport.transport.iceGatherer.getLocalCandidates()
        )

        candidates = list()

        for candidate in rtc_ice_candidates:
            candidate = {
                "candidate": candidate_to_sdp(candidate),
                "sdpMid": candidate.sdpMid if candidate.sdpMid is not None else SDP_MID_DEFAULT,
                "sdpMLineIndex": candidate.sdpMLineIndex is not None
                if candidate.sdpMLineIndex
                else SDP_MLINE_INDEX_DEFAULT,
            }
            candidates.append(candidate)

        wrap_callback(
            callback=candidates_callback,
            candidates=candidates,
            partner_address=rtc_partner.partner_address,
        )
