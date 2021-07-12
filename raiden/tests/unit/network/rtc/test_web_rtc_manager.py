from typing import Any

import pytest
from gevent.event import Event

import raiden.tests.utils.mocks
from raiden.constants import ICEConnectionState
from raiden.network.pathfinding import PFSProxy
from raiden.network.transport.matrix.rtc.aiogevent import yield_future
from raiden.network.transport.matrix.rtc.web_rtc import WebRTCManager
from raiden.tests.utils.factories import make_signer
from raiden.tests.utils.transport import ignore_web_rtc_messages

pytestmark = pytest.mark.asyncio


def _dummy_send(*_args: Any) -> None:
    pass


def test_rtc_partner_close() -> None:
    node_address = make_signer().address
    stop_event = Event()

    pfs_config = raiden.tests.utils.mocks.make_pfs_config()
    pfs_proxy = PFSProxy(pfs_config)
    web_rtc_manager = WebRTCManager(
        node_address, pfs_proxy, ignore_web_rtc_messages, _dummy_send, stop_event
    )

    partner_address = make_signer().address
    rtc_partner = web_rtc_manager.get_rtc_partner(partner_address)
    peer_connection_first = rtc_partner.peer_connection

    msg = "ICEConnectionState should be 'new'"
    assert peer_connection_first.iceConnectionState == "new", msg

    close_task = web_rtc_manager.close_connection(rtc_partner.partner_address)
    yield_future(close_task)

    peer_connection_second = rtc_partner.peer_connection

    msg = "peer connections should be different objects"
    assert peer_connection_first != peer_connection_second, msg
    msg = "New peer connection should be in state 'new'"
    assert peer_connection_second.iceConnectionState == ICEConnectionState.NEW.value, msg
    msg = "Old RTCPeerConnection state should be 'closed' after close()"
    assert peer_connection_first.iceConnectionState == ICEConnectionState.CLOSED.value, msg
    msg = "Should not have ready channel after close()"
    assert not web_rtc_manager.has_ready_channel(partner_address), msg
