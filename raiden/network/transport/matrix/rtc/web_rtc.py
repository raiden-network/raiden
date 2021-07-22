import asyncio
import collections
import json
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
    WEB_RTC_CHANNEL_TIMEOUT,
    ICEConnectionState,
    RTCChannelState,
    RTCMessageType,
    RTCSignallingState,
    SDPTypes,
)
from raiden.network.transport.matrix.client import ReceivedRaidenMessage
from raiden.network.transport.matrix.rtc.aiogevent import yield_future
from raiden.network.transport.matrix.rtc.utils import create_task_callback, wrap_callback
from raiden.network.transport.matrix.utils import validate_and_parse_message
from raiden.utils.formatting import to_checksum_address
from raiden.utils.runnable import Runnable
from raiden.utils.typing import Address, Any, Callable, Coroutine, Dict, List, Optional, Set, Union

log = structlog.get_logger(__name__)


class _CoroutineHandler:
    def __init__(self) -> None:
        super().__init__()
        self.coroutines: List[Task] = list()

    def schedule_task(
        self,
        coroutine: Coroutine,
        callback: Callable[[Any], None] = None,
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
        # This is done to have the bound keywords if it is of type _RTCConnection
        logger = getattr(self, "log", log)
        logger.debug("Waiting for coroutines", coroutines=pending_coroutines)

        try:
            return_values = await asyncio.gather(*pending_coroutines, return_exceptions=True)
            for value in return_values:
                if isinstance(value, Exception):
                    raise value
        except CancelledError:
            logger.debug(
                "Pending coroutines cancelled",
                cancelled=[coroutine for coroutine in self.coroutines if coroutine.cancelled()],
            )

    def join_all_coroutines(self) -> None:
        yield_future(self.wait_for_coroutines())

    def cancel_all_pending(self) -> None:
        for coroutine in self.coroutines:
            if not coroutine.done() and not coroutine.cancelled():
                coroutine.cancel()


class _RTCConnection(_CoroutineHandler):
    @dataclass
    class SyncEvents:
        """
        SyncEvents is a set of events which helps synchronizing the signaling process.
        As not all messages of the signalling process (offer, answer, candidates, hangup) are
        able to be processed in an arbitrary order, the events help to either wait or drop
        incoming messages.

        allow_candidates: when set candidates can be processed
        allow_hangup: when set a hangup message can be processes

        Conditions:

        allow candidates after remote description is set (in process_signalling)
        allow hang up only after at least one other message is received, drop otherwise
        clear hang up after hang up is received

        FIXME: This is not the best maintainable solution. Should be improved in the future
               Data races will be reduced once there are unique call ids per connection
               establishment (not partner)
        """

        aio_allow_candidates: AIOEvent = field(default_factory=AIOEvent)
        aio_allow_hangup: AIOEvent = field(default_factory=AIOEvent)
        reset_event: AIOEvent = field(default_factory=AIOEvent)

        def reset(self) -> None:
            self.reset_event.set()
            self.set_all()
            self.clear_all()

        def set_all(self) -> None:
            self.aio_allow_candidates.set()
            self.aio_allow_hangup.set()

        def clear_all(self) -> None:
            self.aio_allow_candidates.clear()
            self.aio_allow_hangup.clear()

        async def wait_for_candidates(self) -> None:
            await self.aio_allow_candidates.wait()

        async def wait_for_hangup(self) -> None:
            await self.aio_allow_hangup.wait()

    def __init__(
        self,
        partner_address: Address,
        node_address: Address,
        signaling_send: Callable[[Address, str], None],
        _handle_message_callback: Callable[[str, Address], None],
    ) -> None:
        super().__init__()
        self.node_address = node_address
        self.partner_address = partner_address
        self._call_id = self._make_call_id()
        self._signaling_send = signaling_send
        self._handle_message_callback = _handle_message_callback
        self.channel: Optional[RTCDataChannel] = None
        self.sync_events = _RTCConnection.SyncEvents()
        self.log = log.bind(
            node=to_checksum_address(node_address),
            partner_address=to_checksum_address(partner_address),
        )
        self._setup_peer_connection()

    def _setup_peer_connection(self) -> None:
        self.peer_connection = RTCPeerConnection()
        self.peer_connection.on(
            "icegatheringstatechange",
            partial(
                _on_ice_gathering_state_change,
                conn=self,
                candidates_callback=self._handle_candidates_callback,
            ),
        )
        self.peer_connection.on(
            "signalingstatechange",
            partial(_on_signalling_state_change, conn=self),
        )

        self.peer_connection.on(
            "iceconnectionstatechange", partial(_on_ice_connection_state_change, conn=self)
        )

    @staticmethod
    def from_offer(
        partner_address: Address,
        node_address: Address,
        signaling_send: Callable[[Address, str], None],
        handle_message_callback: Callable[[str, Address], None],
        offer: Dict[str, str],
    ) -> "_RTCConnection":
        conn = _RTCConnection(
            partner_address, node_address, signaling_send, handle_message_callback
        )
        conn._call_id = offer["call_id"]
        return conn

    def set_channel_callbacks(self) -> None:
        if self.channel is None:
            return

        self.channel.on(
            "message", partial(_on_channel_message, self, self._handle_message_callback)
        )
        self.channel.on("close", partial(_on_channel_close, self, self.node_address))
        self.channel.on("open", partial(_on_channel_open, self.node_address, self.channel))

    @property
    def call_id(self) -> str:
        return self._call_id

    async def _try_signaling(self, coroutine: Coroutine) -> Optional[Any]:
        try:
            return await coroutine
        except InvalidStateError:
            # this can happen if peer connection gets closed while awaiting in the try block
            self.log.debug(
                "Connection state in incompatible state",
                signaling_state=self.peer_connection.signalingState,
                ice_connection_state=self.peer_connection.iceConnectionState,
            )
            asyncio.create_task(self.close())
            return None

        except AttributeError:
            self.log.exception("Attribute error in coroutine", coroutine=coroutine)
            asyncio.create_task(self.close())
            return None

    async def _set_local_description(self, description: RTCSessionDescription) -> None:
        self.log.debug("Set local description", description=description)
        await self._try_signaling(self.peer_connection.setLocalDescription(description))

    def _make_call_id(self) -> str:
        timestamp = time.time()
        address1, address2 = sorted((self.node_address, self.partner_address))
        return f"{to_checksum_address(address1)}|{to_checksum_address(address2)}|{timestamp}"

    async def initialize_signalling(
        self,
    ) -> Optional[RTCSessionDescription]:
        """Coroutine to create channel. Setting up channel in aiortc"""

        if self.sync_events.reset_event.is_set():
            return None

        self.channel = self.peer_connection.createDataChannel(self.call_id)
        self.set_channel_callbacks()
        offer = await self._try_signaling(self.peer_connection.createOffer())
        if offer is None:
            return None
        self.log.debug("Created offer", offer=offer)

        self.schedule_task(self._set_local_description(offer))
        # hang up messages are allowed to be processed now
        self.sync_events.aio_allow_hangup.set()
        return offer

    async def process_signalling(
        self, description: Dict[str, str]
    ) -> Optional[RTCSessionDescription]:
        """Coroutine to set remote description. Sets remote description in aiortc"""

        if self.sync_events.reset_event.is_set():
            self.log.debug("Reset called. Returning on coroutine")
            return None

        remote_description = RTCSessionDescription(description["sdp"], description["type"])
        sdp_type = description["type"]
        # We need to wait for
        self.log.debug(
            "Wait for existing tasks before setting remote description",
            coroutines=self.coroutines,
        )
        await self.wait_for_coroutines(cancel=False)
        self.log.debug("Set Remote Description", description=description)
        await self._try_signaling(self.peer_connection.setRemoteDescription(remote_description))

        if self.peer_connection.remoteDescription is None:
            return None

        self.sync_events.aio_allow_hangup.set()

        if sdp_type == SDPTypes.ANSWER.value:
            return None

        self.peer_connection.on(
            "datachannel",
            partial(_on_datachannel, self, self.node_address),
        )
        answer = await self._try_signaling(self.peer_connection.createAnswer())
        if answer is None:
            return None

        self.schedule_task(
            self._set_local_description(answer),
            callback=None,
        )
        return answer

    async def set_candidates(self, content: Dict[str, Any]) -> None:

        if self.peer_connection.sctp is None:
            await self.sync_events.wait_for_candidates()
            if self.sync_events.reset_event.is_set():
                self.log.debug("Reset called. Returning on coroutine")
                return None

        assert self.peer_connection.sctp, "SCTP should be set by now"

        for candidate in content["candidates"]:

            rtc_ice_candidate = candidate_from_sdp(candidate["candidate"])
            rtc_ice_candidate.sdpMid = candidate["sdpMid"]
            rtc_ice_candidate.sdpMLineIndex = candidate["sdpMLineIndex"]

            if rtc_ice_candidate.sdpMid != self.peer_connection.sctp.mid:
                self.log.debug(
                    "Invalid candidate. Wrong sdpMid",
                    candidate=candidate,
                    sctp_sdp_mid=self.peer_connection.sctp.mid,
                )
                continue
            await self.peer_connection.addIceCandidate(rtc_ice_candidate)

    async def send_message(self, message: str) -> None:
        """Sends message through aiortc. Not an async function. Output is written to buffer"""

        if self.channel is not None and self.channel.readyState == RTCChannelState.OPEN.value:
            self.log.debug(
                "Sending message in asyncio kingdom",
                channel=self.channel.label,
                message=message,
                time=time.time(),
            )
            self.channel.send(message)

            try:
                # empty outbound queue by transmitting chunks
                await self.peer_connection.sctp._transmit()
                # flush message into outbound queue
                await self.peer_connection.sctp._data_channel_flush()
                # transmit chunks in outbound queue
                await self.peer_connection.sctp._transmit()
            except ConnectionError:
                self.log.debug("Connection error occurred while trying to send message")
                await self.close()
                return

        else:
            self.log.debug(
                "Channel is not open but trying to send a message.",
                ready_state=self.channel.readyState
                if self.channel is not None
                else "No channel exists",
            )

    async def close(self) -> None:
        self.log.debug("Closing peer connection")
        await self.peer_connection.close()
        if self.channel:
            self.channel.close()

    async def reset(self) -> None:
        self.sync_events.reset()
        await self.wait_for_coroutines()
        self.sync_events.reset_event.clear()
        self._setup_peer_connection()
        self.channel = None

    def _handle_candidates_callback(self, candidates: List[Dict[str, Union[int, str]]]) -> None:
        message = {
            "type": RTCMessageType.CANDIDATES.value,
            "candidates": candidates,
            "call_id": self.call_id,
        }
        self._signaling_send(self.partner_address, json.dumps(message))

    def send_hangup_message(self) -> None:
        hangup_message = {
            "type": RTCMessageType.HANGUP.value,
            "call_id": self.call_id,
        }
        self._signaling_send(self.partner_address, json.dumps(hangup_message))

    def handle_sdp_callback(
        self, rtc_session_description: Optional[RTCSessionDescription]
    ) -> None:
        """
        This is a callback function to process sdp (session description protocol) messages.
        These messages are part of the ROAP (RTC Offer Answer Protocol) which is also called
        signalling. Messages are exchanged via Matrix.
        Args:
            rtc_session_description: sdp message for the partner
        """
        if rtc_session_description is None:
            return

        sdp_type = rtc_session_description.type
        message = {
            "type": sdp_type,
            "sdp": rtc_session_description.sdp,
            "call_id": self.call_id,
        }
        self.log.debug(
            f"Send {sdp_type} to partner",
            partner_address=to_checksum_address(self.partner_address),
            sdp_description=message,
        )

        self._signaling_send(self.partner_address, json.dumps(message))


@dataclass
class WebRTCManager(_CoroutineHandler, Runnable):
    def __init__(
        self,
        node_address: Address,
        process_messages: Callable[[List[ReceivedRaidenMessage]], None],
        signaling_send: Callable[[Address, str], None],
        stop_event: GEvent,
    ) -> None:
        super().__init__()
        self.node_address = node_address
        self._process_messages = process_messages
        self._signaling_send = signaling_send
        self._stop_event = stop_event
        # the addresses for which we're currently trying to initialize WebRTC channels
        self._web_rtc_channel_inits: Set[Address] = set()
        self._address_to_connections: Dict[
            Address, Dict[str, _RTCConnection]
        ] = collections.defaultdict(dict)
        self.log = log.bind(node=to_checksum_address(node_address))

    def _handle_message(self, message_data: str, partner_address: Address) -> None:
        messages: List[ReceivedRaidenMessage] = []
        for msg in validate_and_parse_message(message_data, partner_address):
            messages.append(ReceivedRaidenMessage(message=msg, sender=partner_address))
        self._process_messages(messages)

    def _maybe_initialize_web_rtc(self, address: Address) -> None:
        if address in self._web_rtc_channel_inits:
            return

        self.log.debug(
            "Spawning initialize web rtc for partner", partner_address=to_checksum_address(address)
        )
        self._schedule_new_greenlet(self._wrapped_initialize_web_rtc, address)

    def _wrapped_initialize_web_rtc(self, address: Address) -> None:
        self._web_rtc_channel_inits.add(address)
        try:
            return self._initialize_web_rtc(address)
        finally:
            self._web_rtc_channel_inits.remove(address)

    def _initialize_web_rtc(self, partner_address: Address) -> None:
        if self._stop_event.is_set():
            return

        self.log.debug(
            "Initiating web rtc",
            partner_address=to_checksum_address(partner_address),
        )

        conn = _RTCConnection(
            partner_address, self.node_address, self._signaling_send, self._handle_message
        )
        self._add_connection(partner_address, conn)
        self.schedule_task(
            coroutine=conn.initialize_signalling(),
            callback=conn.handle_sdp_callback,
        )

        # wait for WEB_RTC_CHANNEL_TIMEOUT seconds and check if connection was established
        if self._stop_event.wait(timeout=WEB_RTC_CHANNEL_TIMEOUT):
            return

        # if room is not None that means we are at least in the second iteration
        # call hang up to sync with the partner about a retry
        if not self.has_ready_channel(partner_address):
            self.log.debug(
                "Could not establish channel",
                partner_address=to_checksum_address(partner_address),
            )
            conn.send_hangup_message()
            self.close_connection(partner_address)

    def _add_connection(self, partner_address: Address, conn: _RTCConnection) -> None:
        assert (
            len(self._address_to_connections[partner_address]) < 2
        ), "cannot have more than 2 connections per partner"
        assert (
            conn.call_id not in self._address_to_connections[partner_address]
        ), "must not be there already"
        self._address_to_connections[partner_address][conn.call_id] = conn

    def _get_connection(self, partner_address: Address, call_id: str = None) -> _RTCConnection:
        conns = self._address_to_connections[partner_address]
        if call_id is not None:
            return conns[call_id]
        return next(iter(conns.values()))

    def has_ready_channel(self, partner_address: Address) -> bool:
        conns = self._address_to_connections.get(partner_address)
        if conns is None:
            return False
        return any(
            conn.channel is not None and conn.channel.readyState == RTCChannelState.OPEN.value
            for conn in conns.values()
        )

    def _reset_state(self) -> None:
        self._address_to_connections = {}

    def _set_candidates_for_address(
        self, partner_address: Address, content: Dict[str, Any]
    ) -> None:
        conn = self._get_connection(partner_address, content["call_id"])
        self.schedule_task(conn.set_candidates(content))

    def _process_signalling_for_address(
        self, partner_address: Address, rtc_message_type: str, description: Dict[str, str]
    ) -> None:
        if rtc_message_type == RTCMessageType.OFFER.value:
            conn = _RTCConnection.from_offer(
                partner_address,
                self.node_address,
                self._signaling_send,
                self._handle_message,
                description,
            )
            self._add_connection(partner_address, conn)
        else:
            # must exist
            conn = self._get_connection(partner_address)

        self.schedule_task(
            coroutine=conn.process_signalling(description=description),
            callback=conn.handle_sdp_callback,
        )

    def send_message_for_address(self, partner_address: Address, message: str) -> None:
        conn = self._get_connection(partner_address)
        self.schedule_task(conn.send_message(message))

    def health_check(self, partner_address: Address) -> None:
        self._maybe_initialize_web_rtc(partner_address)

    def close_connection(self, partner_address: Address) -> List[Task]:
        conns = self._address_to_connections[partner_address]
        tasks = []
        for conn in conns.values():
            conn.sync_events.clear_all()
            task = self.schedule_task(conn.close())
            tasks.append(task)
        return tasks

    def process_signalling_message(
        self, partner_address: Address, rtc_message_type: str, content: Dict[str, str]
    ) -> None:
        if (
            rtc_message_type in [RTCMessageType.OFFER.value, RTCMessageType.ANSWER.value]
            and "sdp" in content
        ):
            self._process_signalling_for_address(partner_address, rtc_message_type, content)
        elif rtc_message_type == RTCMessageType.HANGUP.value:
            self.close_connection(partner_address)
        elif rtc_message_type == RTCMessageType.CANDIDATES.value:
            self._set_candidates_for_address(partner_address, content)
        else:
            self.log.error(
                "Unknown rtc message type",
                partner_address=to_checksum_address(partner_address),
                type=rtc_message_type,
            )

    def stop(self) -> None:
        self.log.debug("Closing rtc connections")

        for conns in self._address_to_connections.values():
            for conn in conns.values():
                conn.send_hangup_message()

        for partner_address, conns in self._address_to_connections.items():
            tasks = self.close_connection(partner_address)
            for conn in conns.values():
                conn.join_all_coroutines()
            for task in tasks:
                yield_future(task)

        self.join_all_coroutines()
        self._reset_state()


def _on_datachannel(conn: _RTCConnection, node_address: Address, channel: RTCDataChannel) -> None:
    conn.channel = channel
    _on_channel_open(node_address, channel)
    conn.set_channel_callbacks()


def _on_channel_open(node_address: Address, channel: RTCDataChannel) -> None:
    log.debug("Rtc datachannel open", node=to_checksum_address(node_address), label=channel.label)


def _on_channel_close(conn: _RTCConnection, node_address: Address) -> None:
    """callback if channel is closed. It is part of a partial function"""
    if conn.channel is not None:
        log.debug(
            "Rtc datachannel closed",
            node=to_checksum_address(node_address),
            label=conn.channel.label,
        )
        # remove all listeners on channel to not receive events anymore
        conn.channel.remove_all_listeners()
        conn.channel = None
        if conn.peer_connection.iceConnectionState in [
            ICEConnectionState.COMPLETED,
            ICEConnectionState.CHECKING,
        ]:
            conn.schedule_task(conn.close())


def _on_channel_message(
    conn: _RTCConnection, handle_message_callback: Callable[[str, Address], None], message: str
) -> None:
    """callback if message is received. It is part of a partial function"""
    assert conn.channel, "channel not set but received message"
    conn.log.debug(
        "Received message in asyncio kingdom",
        channel=conn.channel.label,
        message=message,
        time=time.time(),
    )

    wrap_callback(
        handle_message_callback, message_data=message, partner_address=conn.partner_address
    )


def _on_ice_gathering_state_change(
    conn: _RTCConnection, candidates_callback: Callable[[List[Dict[str, Union[int, str]]]], None]
) -> None:
    peer_connection = conn.peer_connection
    conn.log.debug("ICE gathering state changed", state=peer_connection.iceGatheringState)

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

        wrap_callback(callback=candidates_callback, candidates=candidates)


def _on_ice_connection_state_change(conn: _RTCConnection) -> None:
    ice_connection_state = conn.peer_connection.iceConnectionState
    conn.log.debug("Ice connection state changed", signaling_state=ice_connection_state)

    if ice_connection_state in [ICEConnectionState.CLOSED.value, ICEConnectionState.FAILED.value]:
        asyncio.create_task(conn.reset())


def _on_signalling_state_change(conn: _RTCConnection) -> None:
    signaling_state = conn.peer_connection.signalingState
    conn.log.debug("Signaling state changed", signaling_state=signaling_state)
    # if signaling state is closed also set allow candidates otherwise
    # coroutine will hang forever
    if signaling_state in [
        RTCSignallingState.HAVE_REMOTE_OFFER.value,
        RTCSignallingState.CLOSED.value,
    ]:
        conn.sync_events.aio_allow_candidates.set()
