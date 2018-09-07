from gevent.event import Event
from gevent.queue import Queue

from raiden.utils import typing, pex


class NotifyingQueue(Event):
    def __init__(self, maxsize=None, items=()):
        super().__init__()
        self._queue = Queue(maxsize, items)

        if items:
            self.set()

    def put(self, item):
        """ Add new item to the queue. """
        self._queue.put(item)
        self.set()

    def get(self, block=True, timeout=None):
        """ Removes and returns an item from the queue. """
        value = self._queue.get(block, timeout)
        if self._queue.empty():
            self.clear()
        return value

    def peek(self, block=True, timeout=None):
        return self._queue.peek(block, timeout)

    def __len__(self):
        return len(self._queue)

    def copy(self):
        """ Copies the current queue items. """
        copy = self._queue.copy()

        result = list()
        while not copy.empty():
            result.append(copy.get_nowait())
        return result


class QueueIdentifier(typing.NamedTuple):
    recipient: typing.Address
    payment_network_identifier: typing.PaymentNetworkID
    # None means queue has messages not tied to any channel
    token_network_identifier: typing.TokenNetworkID = None
    channel_identifier: typing.ChannelID = None
    ordered: bool = False  # default to previously 'global' queue

    def __repr__(self):
        return (
            f'<'
            f'QueueIdentifier recipient:{pex(self.recipient)} '
            f'payment_network:{pex(self.payment_network_identifier)} '
            f'token:{pex(self.token_network_identifier)} '
            f'channelid:{self.channel_identifier}'
            f'>'
        )
