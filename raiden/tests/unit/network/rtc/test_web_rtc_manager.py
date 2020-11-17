import gevent
from raiden.network.transport.matrix.rtc.web_rtc import WebRTCManager
from raiden.tests.utils.factories import make_signer
from raiden.tests.utils.transport import ignore_sdp, ignore_web_rtc_messages


def test_rtc_partner_close():

    web_rtc_manager = WebRTCManager(None, ignore_web_rtc_messages, ignore_sdp)

    node_address = make_signer().address
    web_rtc_manager.node_address = node_address
    partner_address = make_signer().address

    rtc_partner = web_rtc_manager.get_rtc_partner(partner_address)

    web_rtc_manager.close(rtc_partner.partner_address)

    gevent.wait([rtc_partner.partner_ready_event])
