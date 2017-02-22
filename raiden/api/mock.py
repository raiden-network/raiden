from Queue import Queue
from Queue import Empty as QueueEmpty
from time import sleep
from collections import defaultdict

from raiden.api.objects import ChannelList, Channel, ChannelNew
from raiden.api.v1.resources import EventsResoure, ChannelsResource, ChannelsResourceByChannelAddress
from raiden.api.rest import APIServer, RestAPI
from raiden.settings import (
    DEFAULT_REVEAL_TIMEOUT,
    DEFAULT_SETTLE_TIMEOUT,
)

from raiden.utils import make_address


class MockAPI(object):
    """
    Mostly for returning the right classes for the RESTfulAPI's encoding,
    filled with mock-data or data based on user-input (channel creation).

    Does some manipulation on the Channel objects based on api actions,
    but is no proper Tester module that emulates Raidens internal logic

    This will define the Interface of the RaidenAPI.
    The RaidenAPI shouldn't return e.g. a raiden.channel.Channel object,
    but rather just a Data container object (raiden.api.rest_api.Channel),
    filled with binary/decoded data

    Reason for this: we want to keep the interface for external/in-process users of the API the same.
    Also, if we introduce additional logic just for the API to e.g. the Channel object,
    we want to separate internal from external logic.
    """
    channel_by_address = dict() # 1:1
    all_channel = [] # N
    channels_by_token = defaultdict(list) # 1:N
    channels_by_partner = defaultdict(list) # 1:N
    event_queue = Queue()
    block_number = 0

    # To emulate mining, the block_number will increase after every public method call with a 50% success rate
    def _mine_new_block_try(self):
        import random
        success = random.choice([True, False])
        if success == True:
            self.block_number += 1

    def _get_channel_by_token_and_partner(self, token, partner):
        list_ = self.channels_by_token[token]
        for channel in list_:
            if channel.partner_address == partner:
                return channel

    def _add_channel(self, channel):
        self.channel_by_address[channel.channel_address] = channel

        channels_by_token_list = self.channels_by_token[channel.token_address]
        channels_by_token_list.append(channel)

        channels_by_partner_list = self.channels_by_partner[channel.partner_address]
        channels_by_partner_list.append(channel)

        self.all_channel.append(channel)

    def _queue_event(self, event):
        self.event_queue.put(event)

    def _consume_event_queue(self):
        """
        The simplistic event queue will get popped empty.
        :return: returns a list of all objects currently in the Queue
        """

        event_list = []

        while True:
            try:
                event = self.event_queue.get()
                event_list.append(event)
            except QueueEmpty():
                break

        return event_list

    def open(self, token_address, partner_address, settle_timeout=None, reveal_timeout=None):
        existing_channel = self._get_channel_by_token_and_partner(token_address, partner_address)
        if existing_channel:
            channel = existing_channel
        else:
            netting_channel_address = make_address() # the new channel address
            channel = Channel(
                netting_channel_address,
                token_address,
                partner_address,
                settle_timeout or DEFAULT_SETTLE_TIMEOUT,
                reveal_timeout or DEFAULT_REVEAL_TIMEOUT,
                deposit=0,
                status='open'
            )

            self._add_channel(channel)

            event = ChannelNew(netting_channel_address, token_address, partner_address, self.block_number)

            self._queue_event(event)

        self._mine_new_block_try()
        return channel

    def close(self, channel_address):
        existing_channel = self.channel_by_address[channel_address]

        # modify field in place
        existing_channel.status = 'closed'

        self._mine_new_block_try()
        return existing_channel

    def deposit(self, token_address, partner_address, deposit):
        channel = None
        successful = False
        existing_channel = self._get_channel_by_token_and_partner(token_address, partner_address)
        if existing_channel:
            if existing_channel.deposit < deposit:
                existing_channel.deposit = deposit
                channel = existing_channel
                successful = True
            else:
                channel = existing_channel

        self._mine_new_block_try()
        return channel

    def get_channel_list(self, token_address=None, partner_address=None):
        channels = list()

        if token_address is not None:
            channels = self.channels_by_token[token_address]

        if partner_address is not None:
            channels = self.channels_by_partner[partner_address]

        if token_address is None and partner_address is None:
            channels = self.all_channel

        self._mine_new_block_try()
        return channels

    def get_channel(self, channel_address):
        channel = self.channel_by_address[channel_address]

        self._mine_new_block_try()
        return channel

    def get_new_events(self):
        while self.event_queue.empty():
            sleep(1)

        event_list = self._consume_event_queue()

        self._mine_new_block_try()
        return event_list

    def transfer(self):
        raise NotImplementedError()

    def exchange(self):
        raise NotImplementedError()

    def expect_exchange(self):
        raise NotImplementedError()


if __name__ == '__main__':

    mock_api = MockAPI()
    rest_api = RestAPI(mock_api)

    api_server = APIServer(rest_api)
    api_server.run(5001, debug=True)
