import pytest

from raiden.constants import ICEConnectionState
from raiden.network.transport.matrix.rtc.aiogevent import yield_future
from raiden.network.transport.matrix.rtc.web_rtc import WebRTCManager
from raiden.tests.utils.factories import make_signer
from raiden.tests.utils.transport import (
    ignore_candidates,
    ignore_close,
    ignore_sdp,
    ignore_web_rtc_messages,
)

pytestmark = pytest.mark.asyncio


def test_rtc_partner_close() -> None:
    node_address = make_signer().address

    web_rtc_manager = WebRTCManager(
        node_address, ignore_web_rtc_messages, ignore_sdp, ignore_candidates, ignore_close
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
