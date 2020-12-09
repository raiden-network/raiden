import asyncio
import time
from asyncio import CancelledError, Event as AIOEvent, Task
from dataclasses import dataclass, field
from functools import partial

import structlog
from aiortc import InvalidStateError, RTCDataChannel, RTCPeerConnection, RTCSessionDescription
from aiortc.sdp import candidate_from_sdp, candidate_to_sdp
from gevent.event import Event as GEvent

from raiden.constants import (
    SDP_MID_DEFAULT,
    SDP_MLINE_INDEX_DEFAULT,
    ICEConnectionState,
    RTCChannelState,
    RTCSignallingState,
    SDPTypes,
)
from raiden.network.transport.matrix.rtc.aiogevent import yield_aio_event, yield_future
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

    async def wait_for_coroutines(self, cancel: bool = True) -> None:

        if cancel:
            self.cancel_all_pending()

        pending_coroutines = [coroutine for coroutine in self.coroutines if not coroutine.done()]
        log.debug("Waiting for coroutines", coroutines=pending_coroutines)

        try:
            await asyncio.gather(*pending_coroutines, return_exceptions=True)
        except CancelledError:
            log.debug(
                "Pending coroutines cancelled",
                cancelled=[coroutine for coroutine in self.coroutines if coroutine.cancelled()],
            )

    def join_all_coroutines(self) -> None:
        yield_future(self.wait_for_coroutines())

    def cancel_all_pending(self) -> None:
        for coroutine in self.coroutines:
            if not coroutine.done() and not coroutine.cancelled():
                coroutine.cancel()


class RTCPartner(CoroutineHandler):
    @dataclass
    class SyncEvents:
        """
        SyncEvents is a set of events which helps synchronizing the signaling process.
        As not all messages of the signalling process (offer, answer, candidates, hangup) are
        able to be processed in an arbitrary order, the events help to either wait or drop
        incoming messages.

        allow_init: when set offers and answers can be processed
        allow_candidates: when set candidates can be processed
        allow_hangup: when set a hangup message can be processes

        Conditions:

        allow candidates after remote description is set (in process_signalling)
        allow init only if partner is reachable
        after remote_description being received clear allow_init (only one offer per cycle)
        allow hang up only after at least one other message is received, drop otherwise
        clear hang up after hang up is received

        FIXME: This is not the best maintainable solution. Should be improved in the future
               Data races will be reduced once there are unique call ids per connection
               establishment (not partner)
        """

        aio_allow_init: AIOEvent = field(default_factory=AIOEvent)
        aio_allow_candidates: AIOEvent = field(default_factory=AIOEvent)
        aio_allow_hangup: AIOEvent = field(default_factory=AIOEvent)
        reset_event: AIOEvent = field(default_factory=AIOEvent)

        def __post_init__(self) -> None:
            self.aio_allow_init.set()

        @property
        def g_allow_init(self) -> GEvent:
            return yield_aio_event(self.aio_allow_init)

        def reset(self) -> None:
            self.reset_event.set()
            self.set_all()
            self.clear_all()
            self.aio_allow_init.set()

        def set_all(self) -> None:
            self.aio_allow_init.set()
            self.aio_allow_candidates.set()
            self.aio_allow_hangup.set()

        def clear_all(self) -> None:
            self.aio_allow_init.clear()
            self.aio_allow_candidates.clear()
            self.aio_allow_hangup.clear()

        async def wait_for_init(self) -> None:
            await self.aio_allow_init.wait()

        async def wait_for_candidates(self) -> None:
            await self.aio_allow_candidates.wait()

        async def wait_for_hangup(self) -> None:
            await self.aio_allow_hangup.wait()

    def __init__(self, partner_address: Address, peer_connection: RTCPeerConnection) -> None:
        super().__init__()
        self.partner_address = partner_address
        self.peer_connection = peer_connection
        self.channel: Optional[RTCDataChannel] = None
        self.sync_events = RTCPartner.SyncEvents()

    def _setup_channel(self, node_address: Address) -> None:
        lower_address = my_place_or_yours(node_address, self.partner_address)
        higher_address = self.partner_address if lower_address == node_address else node_address
        channel_name = (
            f"{to_checksum_address(lower_address)}|{to_checksum_address(higher_address)}"
        )
        self.channel = self.peer_connection.createDataChannel(channel_name)

    def set_channel_callbacks(
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
        self.channel.on("close", partial(on_channel_close, self, node_address))
        self.channel.on("open", partial(on_channel_open, node_address, self.channel))

    def get_call_id(self, node_address: Address) -> str:
        lower_address = my_place_or_yours(node_address, self.partner_address)
        higher_address = self.partner_address if lower_address == node_address else node_address
        call_id = f"{to_checksum_address(lower_address)}|{to_checksum_address(higher_address)}"
        return call_id

    async def _set_local_description(
        self, description: RTCSessionDescription, node_address: Address
    ) -> None:
        try:
            log.debug(
                "Set local description",
                node_address=to_checksum_address(node_address),
                partner_address=to_checksum_address(self.partner_address),
                description=description,
            )
            await self.peer_connection.setLocalDescription(description)
        except InvalidStateError:
            # this can happen if peer connection gets closed while awaiting in the try block
            log.debug(
                "Connection state in incompatible state",
                partner_address=to_checksum_address(self.partner_address),
                signaling_state=self.peer_connection.signalingState,
                ice_connection_state=self.peer_connection.iceConnectionState,
            )
            return None

    async def initialize_signalling(
        self,
        node_address: Address,
        handle_message_callback: Callable[[str, Address], None],
    ) -> Optional[RTCSessionDescription]:
        """Coroutine to create channel. Setting up channel in aiortc"""

        await self.sync_events.aio_allow_init.wait()
        if self.sync_events.reset_event.is_set():
            return None

        self._setup_channel(node_address)
        try:
            offer = await self.peer_connection.createOffer()
        except InvalidStateError:
            # this can happen if peer connection gets closed while awaiting in the try block
            log.debug(
                "Connection state in incompatible state",
                node_address=to_checksum_address(node_address),
                partner_address=to_checksum_address(self.partner_address),
                signaling_state=self.peer_connection.signalingState,
                ice_connection_state=self.peer_connection.iceConnectionState,
            )
            return None

        self.schedule_task(self._set_local_description(offer, node_address))

        self.set_channel_callbacks(node_address, handle_message_callback)
        log.debug(
            "Created offer",
            offer=offer,
            node_address=to_checksum_address(node_address),
            partner_address=to_checksum_address(self.partner_address),
        )

        self.sync_events.aio_allow_hangup.set()
        return offer

    async def process_signalling(
        self,
        node_address: Address,
        description: Dict[str, str],
        handle_message_callback: Callable[[str, Address], None],
    ) -> Optional[RTCSessionDescription]:
        """Coroutine to set remote description. Sets remote description in aiortc"""

        await self.sync_events.aio_allow_init.wait()
        if self.sync_events.reset_event.is_set():
            log.debug(
                "Reset called. Returning on coroutine",
                node_address=to_checksum_address(node_address),
                partner_address=to_checksum_address(self.partner_address),
            )
            return None

        remote_description = RTCSessionDescription(description["sdp"], description["type"])
        sdp_type = description["type"]
        # We need to wait for
        log.debug(
            "Wait for existing tasks before setting remote description",
            coroutines=self.coroutines,
            node_address=to_checksum_address(node_address),
        )
        await self.wait_for_coroutines(cancel=False)
        if self.peer_connection.remoteDescription:
            log.debug(
                "Remote description already set",
                node=to_checksum_address(node_address),
                partner_address=to_checksum_address(self.partner_address),
            )
            return None

        log.debug(
            "Set Remote Description",
            node_address=to_checksum_address(node_address),
            partner_address=to_checksum_address(self.partner_address),
            description=description,
        )
        try:
            await self.peer_connection.setRemoteDescription(remote_description)
        except InvalidStateError:
            # this can happen if peer connection gets closed while awaiting in the try block
            log.debug(
                "Connection state in incompatible state",
                node_address=to_checksum_address(node_address),
                partner_address=to_checksum_address(self.partner_address),
                signaling_state=self.peer_connection.signalingState,
                ice_connection_state=self.peer_connection.iceConnectionState,
            )
            return None

        finally:
            self.sync_events.aio_allow_hangup.set()
            self.sync_events.aio_allow_init.clear()

        if sdp_type == SDPTypes.ANSWER.value:
            return None

        self.peer_connection.on(
            "datachannel", partial(on_datachannel, self, node_address, handle_message_callback)
        )
        answer = await self.peer_connection.createAnswer()
        self.schedule_task(
            self._set_local_description(answer, node_address),
            callback=None,
        )
        return answer

    async def set_candidates(self, content: Dict[str, Any], node_address: Address) -> None:

        if self.peer_connection.sctp is None:
            await self.sync_events.wait_for_candidates()
            if self.sync_events.reset_event.is_set():
                log.debug(
                    "Reset called. Returning on coroutine",
                    node_address=to_checksum_address(node_address),
                    partner_address=to_checksum_address(self.partner_address),
                )
                return None

        assert self.peer_connection.sctp, "SCTP should be set by now"

        for candidate in content["candidates"]:

            rtc_ice_candidate = candidate_from_sdp(candidate["candidate"])
            rtc_ice_candidate.sdpMid = candidate["sdpMid"]
            rtc_ice_candidate.sdpMLineIndex = candidate["sdpMLineIndex"]

            if rtc_ice_candidate.sdpMid != self.peer_connection.sctp.mid:
                log.debug(
                    "Invalid candidate. Wrong sdpMid",
                    node_address=to_checksum_address(node_address),
                    candidate=candidate,
                    sctp_sdp_mid=self.peer_connection.sctp.mid,
                )
                continue
            log.debug(
                "Adding ICE candidate",
                node_address=to_checksum_address(node_address),
                partner_address=to_checksum_address(self.partner_address),
                candidate=candidate,
            )
            await self.peer_connection.addIceCandidate(rtc_ice_candidate)
        candidates = self.peer_connection.sctp.transport.transport.getRemoteCandidates()
        log.debug(
            "Remote candidates",
            candidates=[f"candidate:{candidate_to_sdp(candidate)}" for candidate in candidates],
            node_address=to_checksum_address(node_address),
            partner_address=to_checksum_address(self.partner_address),
            sctp_sdp_mid=self.peer_connection.sctp.mid,
        )

    async def send_message(self, message: str, node_address: Address) -> None:
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
            start_time = time.monotonic()
            try:
                while (
                    self.peer_connection.sctp._data_channel_queue
                    or self.peer_connection.sctp._outbound_queue
                ):
                    await self.peer_connection.sctp._data_channel_flush()
                    while self.peer_connection.sctp._outbound_queue:
                        await self.peer_connection.sctp._transmit()
            except ConnectionError:
                log.debug(
                    "Connection error occurred while trying to send message",
                    node_address=to_checksum_address(node_address),
                    partner_address=to_checksum_address(self.partner_address),
                )
                await self.close(node_address)
                return

            end_time = time.monotonic()
            log.debug("Channel Flush", duration=end_time - start_time)

        else:
            log.debug(
                "Channel is not open but trying to send a message.",
                node=to_checksum_address(node_address),
                partner_address=to_checksum_address(self.partner_address),
                ready_state=self.channel.readyState
                if self.channel is not None
                else "No channel exists",
            )

    async def close(self, node_address: Address) -> None:
        log.debug(
            "Closing peer connection",
            node_address=to_checksum_address(node_address),
            partner_address=to_checksum_address(self.partner_address),
        )

        await self.peer_connection.close()
        if self.channel:
            self.channel.close()

    async def reset(self) -> None:
        self.sync_events.reset()
        await self.wait_for_coroutines()
        self.sync_events.reset_event.clear()
        self.peer_connection = RTCPeerConnection()
        self.channel = None


class WebRTCManager(CoroutineHandler):
    def __init__(
        self,
        node_address: Optional[Address],
        _handle_message_callback: Callable[[str, Address], None],
        _handle_sdp_callback: Callable[[Optional[RTCSessionDescription], Address], None],
        _handle_candidates_callback: Callable[[List[Dict[str, Union[int, str]]], Address], None],
        _close_connection_callback: Callable[[Address], None],
    ) -> None:
        super().__init__()
        self.node_address = node_address
        self._handle_message_callback = _handle_message_callback
        self._handle_sdp_callback = _handle_sdp_callback
        self._handle_candidates_callback = _handle_candidates_callback
        self._close_connection_callback = _close_connection_callback
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
            peer_connection.on(
                "signalingstatechange",
                partial(
                    on_signalling_state_change,
                    rtc_partner=rtc_partner,
                    node_address=self.node_address,
                ),
            )

            peer_connection.on(
                "iceconnectionstatechange",
                partial(
                    on_ice_connection_state_change,
                    rtc_partner=rtc_partner,
                    node_address=self.node_address,
                    closed_callback=self._close_connection_callback,
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
        self.schedule_task(rtc_partner.set_candidates(content, self.node_address))

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

    def send_message_for_address(self, partner_address: Address, message: str) -> None:
        assert self.node_address, "Transport is not started yet but tried to send message"
        rtc_partner = self.address_to_rtc_partners[partner_address]
        self.schedule_task(rtc_partner.send_message(message, self.node_address))

    def close_connection(self, partner_address: Address) -> Optional[Task]:
        msg = "Transport not yet started but tried to close connection"
        assert self.node_address, msg

        rtc_partner = self.address_to_rtc_partners.get(partner_address, None)

        if rtc_partner is not None:
            rtc_partner.sync_events.clear_all()
            return self.schedule_task(rtc_partner.close(self.node_address))

        return None

    def stop(self) -> None:
        msg = "Transport not yet started but tried to stop web rtc manager"
        assert self.node_address, msg

        log.debug("Closing rtc connections", node=to_checksum_address(self.node_address))

        for partner_address in list(self.address_to_rtc_partners.keys()):
            if partner_address in self.address_to_rtc_partners:
                rtc_partner = self.address_to_rtc_partners[partner_address]
                self.close_connection(partner_address)
                rtc_partner.join_all_coroutines()

        self.join_all_coroutines()
        self._reset_state()


def on_datachannel(
    rtc_partner: RTCPartner,
    node_address: Address,
    handle_message_callback: Callable[[str, Address], None],
    channel: RTCDataChannel,
) -> None:
    rtc_partner.channel = channel
    on_channel_open(node_address, channel)
    rtc_partner.set_channel_callbacks(node_address, handle_message_callback)


def on_channel_open(node_address: Address, channel: RTCDataChannel) -> None:
    log.debug("Rtc datachannel open", node=to_checksum_address(node_address), label=channel.label)


def on_channel_close(rtc_partner: RTCPartner, node_address: Address) -> None:
    """callback if channel is closed. It is part of a partial function"""
    if rtc_partner.channel is not None:
        log.debug(
            "Rtc datachannel closed",
            node=to_checksum_address(node_address),
            label=rtc_partner.channel.label,
        )
        # remove all listeners on channel to not receive events anymore
        rtc_partner.channel.remove_all_listeners()
        rtc_partner.channel = None
        if rtc_partner.peer_connection.iceConnectionState in [
            ICEConnectionState.COMPLETED,
            ICEConnectionState.CHECKING,
        ]:
            rtc_partner.schedule_task(rtc_partner.close(node_address))


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
                "candidate": f"candidate:{candidate_to_sdp(candidate)}",
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


def on_ice_connection_state_change(
    rtc_partner: RTCPartner, node_address: Address, closed_callback: Callable[[Address], None]
) -> None:
    ice_connection_state = rtc_partner.peer_connection.iceConnectionState
    log.debug(
        "Ice connection state changed",
        node=to_checksum_address(node_address),
        partner_address=to_checksum_address(rtc_partner.partner_address),
        signaling_state=ice_connection_state,
    )
    if ice_connection_state in [ICEConnectionState.CLOSED.value, ICEConnectionState.FAILED.value]:
        asyncio.create_task(rtc_partner.reset())
        wrap_callback(callback=closed_callback, partner_address=rtc_partner.partner_address)


def on_signalling_state_change(rtc_partner: RTCPartner, node_address: Address) -> None:
    signaling_state = rtc_partner.peer_connection.signalingState
    log.debug(
        "Signaling state changed",
        node=to_checksum_address(node_address),
        partner_address=to_checksum_address(rtc_partner.partner_address),
        signaling_state=signaling_state,
    )
    # if signaling state is closed also set allow candidates otherwise
    # coroutine will hang forever
    if signaling_state in [
        RTCSignallingState.HAVE_REMOTE_OFFER.value,
        RTCSignallingState.CLOSED.value,
    ]:
        rtc_partner.sync_events.aio_allow_candidates.set()
