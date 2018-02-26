# -*- coding: utf-8 -*-
import logging

import gevent

from raiden.messages import decode
from raiden.network.transport import (
    DummyPolicy,
    DummyTransport,
)
from raiden.utils import pex, sha3

log = logging.getLogger(__name__)  # pylint: disable=invalid-name


class MessageLoggerTransport(DummyTransport):
    def __init__(
            self,
            host,
            port,
            protocol=None,
            throttle_policy=DummyPolicy()):

        super().__init__(host, port, protocol, throttle_policy)
        self.addresses_to_messages = dict()

    def send(self, sender, host_port, bytes_):
        self.addresses_to_messages.setdefault(sender.address, []).append(decode(bytes_))
        super().network.send(sender, host_port, bytes_)

    def get_sent_messages(self, node_address):
        return self.addresses_to_messages.get(node_address, [])


class UnreliableTransport(DummyTransport):
    """ A transport that simulates random losses of UDP messages.

    Note:
        The transport is not shared among the instances.
    """

    def __init__(
            self,
            host,
            port,
            protocol=None,
            throttle_policy=DummyPolicy()):

        super().__init__(host, port, protocol, throttle_policy)
        self.droprate = 0

    def send(self, sender, host_port, bytes_):
        # even dropped packages have to go through throttle_policy
        gevent.sleep(self.throttle_policy.consume(1))

        if self.droprate:
            drop = self.network.counter % self.droprate == 0
        else:
            drop = False

        if not drop:
            self.network.send(sender, host_port, bytes_)
        else:
            # since this path wont go to super.send we need to call track
            # ourselves
            self.network.track_send(sender, host_port, bytes_)

            log.debug(
                'dropped packet',
                sender=pex(str(sender).encode()),
                counter=self.network.counter,
                msghash=pex(sha3(bytes_))
            )
