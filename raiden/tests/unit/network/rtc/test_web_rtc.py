import collections
import json
from typing import List

import gevent
import pytest
from gevent.event import Event

from raiden.network.transport.matrix.client import ReceivedRaidenMessage
from raiden.network.transport.matrix.rtc.web_rtc import WebRTCManager
from raiden.tests.utils.factories import make_signer
from raiden.utils.typing import Address

pytestmark = pytest.mark.asyncio


def _ignore_web_rtc_messages(_messages: List[ReceivedRaidenMessage]) -> None:
    pass


class _Transport:
    def __init__(self, address: Address, other_side: WebRTCManager):
        self._messages: collections.deque = collections.deque()
        self._address = address
        self._other_side = other_side

    def send(self, address: Address, message: str) -> None:
        self._messages.appendleft(message)
        content = json.loads(message)
        rtc_message_type = content["type"]
        self._other_side.process_signalling_message(self._address, rtc_message_type, content)


def test_basics() -> None:
    address1 = make_signer().address
    address2 = make_signer().address
    stop_event1 = Event()
    stop_event2 = Event()

    def _send_to_1(*args, **kwargs) -> None:  # type: ignore
        transport2.send(*args, **kwargs)

    def _send_to_2(*args, **kwargs) -> None:  # type: ignore
        transport1.send(*args, **kwargs)

    manager1 = WebRTCManager(address1, _ignore_web_rtc_messages, _send_to_2, stop_event1)
    manager2 = WebRTCManager(address2, _ignore_web_rtc_messages, _send_to_1, stop_event2)

    transport1 = _Transport(address1, manager2)
    transport2 = _Transport(address2, manager1)

    assert not manager1.has_ready_channel(address2), "no channel should exist yet"
    assert not manager2.has_ready_channel(address1), "no channel should exist yet"

    manager1.health_check(address2)
    while not manager1.has_ready_channel(address2):
        gevent.sleep(0.1)

    assert manager2.has_ready_channel(address1), "manager2 must see the channel opened by manager1"

    # close the channel and make sure it goes away on both sides
    manager1.close_connection(address2)

    while manager2.has_ready_channel(address1):
        gevent.sleep(0.1)

    while manager1.has_ready_channel(address2):
        gevent.sleep(0.1)
