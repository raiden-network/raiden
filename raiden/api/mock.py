from Queue import Queue
from Queue import Empty as QueueEmpty
from time import sleep
from collections import defaultdict

from raiden.api.objects import ChannelList, Result, AddressFilter, Channel, ChannelNew
from raiden.api.resources import EventsResoure, ChannelsResource, ChannelsResourceByAsset
from raiden.api.rest import RestfulAPI, APIWrapper
from raiden.raiden_service import DEFAULT_REVEAL_TIMEOUT, DEFAULT_SETTLE_TIMEOUT

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
    channels_by_asset = defaultdict(list) # 1:N
    channels_by_partner = defaultdict(list) # 1:N
    event_queue = Queue()
    # will get raised +1 after every public method call FIXME:
    block_number = 0

    def _get_channel_by_asset_and_partner(self, asset, partner):
        list_ = self.channels_by_asset[asset]
        for channel in list_:
            if channel.partner_address == partner:
                return channel

    def _add_channel(self, channel):
        self.channel_by_address[channel.channel_address] = channel

        channels_by_asset_list = self.channels_by_asset[channel.asset_address]
        channels_by_asset_list.append(channel)

        channels_by_partner_list = self.channels_by_partner[channel.partner_address]
        channels_by_partner_list.append(channel)

        self.all_channel.append(channel)

    def _queue_event(self, event):
        self.event_queue.put(event)

    def _consume_event_queue(self):

        event_list = []

        while True:
            try:
                event = self.event_queue.get()
                event_list.append(event)
            except QueueEmpty():
                break
            else:
                sleep(0.01)  # TODO CHECKME

        return event_list

    def open(self, asset_address, partner_address, settle_timeout,reveal_timeout):
        existing_channel = self._get_channel_by_asset_and_partner(asset_address, partner_address)
        if existing_channel:
            result = Result(successful=False, data=existing_channel)
        else:
            netting_channel_address = make_address() # the new channel address
            channel = Channel(
                netting_channel_address,
                asset_address,
                partner_address,
                settle_timeout or DEFAULT_SETTLE_TIMEOUT,
                reveal_timeout or DEFAULT_REVEAL_TIMEOUT,
                amount=0,
                status='open'
            )

            self._add_channel(channel)

            event = ChannelNew(netting_channel_address, asset_address, partner_address, self.block_number)

            result = Result(successful=True, data=channel)

            self._queue_event(event)

        self.block_number += 1
        return result

    def close(self, asset_address, partner_address):
        existing_channel = self._get_channel_by_asset_and_partner(asset_address, partner_address)
        existing_channel.status = 'closed'

        result = Result(successful=True, data=existing_channel)
        self.block_number += 1
        return result

    def deposit(self, asset_address, partner_address, amount):
        channel = None
        successful = False
        existing_channel = self._get_channel_by_asset_and_partner(asset_address, partner_address)
        if existing_channel:
            if existing_channel.amount < amount:
                existing_channel.amount = amount
                channel = existing_channel
                successful = True
            else:
                channel = existing_channel

        result = Result(successful=successful, data=channel)

        self.block_number += 1
        return result

    def get_channel_list(self, asset_address=None, partner_address=None):
        # TODO allow multiple filters like two asset addresses
        channels = list()

        if asset_address is not None:
            channels = self.channels_by_asset[asset_address]

        if partner_address is not None:
            channels = self.channels_by_partner[partner_address]

        if asset_address is None and partner_address is None:
            channels = self.all_channel

        filter = list()
        if asset_address is not None:
            filter.append(AddressFilter('asset_address', asset_address))
        if partner_address is not None:
            filter.append(AddressFilter('partner_address', partner_address))
        channel_list = ChannelList(channels, filter)

        self.block_number += 1
        return channel_list

    def get_channel(self, channel_address):
        channel = self.channel_by_address[channel_address]

        self.block_number += 1
        return channel

    def get_new_events(self):
        while self.event_queue.empty():
            sleep(1)

        event_list = self._consume_event_queue()

        self.block_number += 1
        return event_list

if __name__ == '__main__':

    mock_api = MockAPI()
    wrapped_api = APIWrapper(mock_api)

    rest_api = RestfulAPI(wrapped_api)
    rest_api.register_type_converters()

    for klass in [ChannelsResource, ChannelsResourceByAsset, EventsResoure]:
        rest_api.add_resource(klass, klass._route)

    rest_api.run(5001, debug=True)

