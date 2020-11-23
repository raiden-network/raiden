import pytest

from raiden.network.transport.matrix.rtc.aiogevent import yield_future
from raiden.network.transport.matrix.rtc.web_rtc import WebRTCManager
from raiden.tests.utils.factories import make_signer
from raiden.tests.utils.transport import ignore_candidates, ignore_sdp, ignore_web_rtc_messages

pytestmark = pytest.mark.asyncio


def test_rtc_partner_close():

    web_rtc_manager = WebRTCManager(None, ignore_web_rtc_messages, ignore_sdp, ignore_candidates)

    node_address = make_signer().address
    web_rtc_manager.node_address = node_address
    partner_address = make_signer().address
    rtc_partner = web_rtc_manager.get_rtc_partner(partner_address)

    msg = "ICEConnectionState should be 'new'"
    assert rtc_partner.peer_connection.iceConnectionState == "new", msg

    close_task = web_rtc_manager.close_connection(rtc_partner.partner_address)
    yield_future(close_task)

    msg = "Should not have ready channel after close()"
    assert not web_rtc_manager.has_ready_channel(partner_address), msg
    msg = "Should not have rtc_partner in manager after close()"
    assert partner_address not in web_rtc_manager.address_to_rtc_partners, msg
    msg = "Old RTCPeerConnection state should be 'closed' after close()"
    assert rtc_partner.peer_connection.iceConnectionState == "closed", msg
