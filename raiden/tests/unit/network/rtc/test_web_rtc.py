import collections
import json
import os
import sys
from typing import Any, List

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
        self._other_side.process_signaling_message(self._address, rtc_message_type, content)


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

    manager1.stop()
    manager2.stop()


def _get_file_descriptors() -> List:
    pid = os.getpid()
    return os.listdir(f"/proc/{pid}/fd/")


@pytest.mark.skipif(sys.platform != "linux", reason="this is a Linux-only test")
@pytest.mark.skipif(sys.version_info < (3, 8), reason="it seems we leak on Python < 3.8")
def test_leak_file_descriptors(monkeypatch: Any) -> None:
    address1 = make_signer().address
    address2 = make_signer().address
    stop_event1 = Event()
    stop_event2 = Event()

    def _noop_send(*args, **kwargs) -> None:  # type: ignore
        pass

    manager1 = WebRTCManager(address1, _ignore_web_rtc_messages, _noop_send, stop_event1)
    manager2 = WebRTCManager(address2, _ignore_web_rtc_messages, _noop_send, stop_event2)

    assert not manager1.has_ready_channel(address2), "no channel should exist yet"
    assert not manager2.has_ready_channel(address1), "no channel should exist yet"

    # reduce the channel init timeout so that the test does not take too long
    monkeypatch.setattr(manager1, "get_channel_init_timeout", lambda *_: 3.0)

    max_open_fds = 0
    for x in range(20):
        manager1.health_check(address2)
        gevent.sleep(manager1.get_channel_init_timeout())
        assert not manager1.has_ready_channel(address2), "must not be ready"
        fds = _get_file_descriptors()
        count = len(fds)
        if x < 4:
            # a few rounds should be enough to get a good upper bound on the
            # number of open file descriptors
            max_open_fds = max(count, max_open_fds)
        else:
            assert count <= max_open_fds, "possible leakage of file descriptors"

    manager1.stop()
    manager2.stop()
