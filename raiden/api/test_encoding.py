import random
import pytest

from raiden.channel import Channel, ChannelEndState, ChannelExternalState
from raiden.utils import make_address, make_privkey_address

from raiden.api.encoding import ChannelListSchema
from raiden.api.objects import ChannelList
from raiden.api.objects import Channel as ChannelContainer

class NettingChannelMock(object):
    # pylint: disable=no-self-use

    def opened(self):
        return 1

    def closed(self):
        return 0

    def settled(self):
        return 0


def make_external_state():
    block_alarm = list()
    channel_for_hashlock = list()
    netting_channel = NettingChannelMock()
    netting_channel.address = make_address()

    external_state = ChannelExternalState(
        block_alarm.append,
        lambda *args: channel_for_hashlock.append(args),
        lambda: 1,
        netting_channel,
    )

    return external_state

@pytest.fixture()
def num_channels():
    return 10

@pytest.fixture()
def channel_list_mock(num_channels):
    channel_list = []
    for _ in range(0,num_channels):
        netting_channel = NettingChannelMock()
        asset_address = make_address()
        privkey1, address1 = make_privkey_address()
        address2 = make_address()

        balance1 = random.randint(0, 2**128)
        balance2 = random.randint(0, 2**128)

        reveal_timeout = random.randint(0, 2**64)
        settle_timeout = reveal_timeout + random.randint(0, 2**64)

        our_state = ChannelEndState(address1, balance1, netting_channel.opened)
        partner_state = ChannelEndState(address2, balance2, netting_channel.opened)
        external_state = make_external_state()

        test_channel = Channel(
            our_state, partner_state, external_state,
            asset_address, reveal_timeout, settle_timeout,
        )

        channel_list.append(test_channel)

    return channel_list

def test_channel_list(channel_list_mock):
    assert isinstance(channel_list_mock, list)
    # has to be wrapped in a ChannelList, which uses same interface as list
    channel_list = ChannelList(channel_list_mock)
    schema = ChannelListSchema()
    ser_iterable = schema.dump(channel_list).data

    # we cannot construct an internal Channel from serialized data directly, because not all information is encoded!
    # so we use a data container that stores all relevant fields
    #
    deser_iterable = schema.load(ser_iterable).data

    for channel, channel_container in zip(channel_list, deser_iterable):
        assert isinstance(channel, Channel)
        assert isinstance(channel_container, ChannelContainer)
        assert channel.__class__ != channel_container.__class__
        assert channel.status == channel_container.status
        assert channel.partner_address == channel_container.partner_address
        assert channel.channel_address == channel_container.channel_address
        assert channel.deposit == channel_container.deposit
        assert channel.reveal_timeout == channel_container.reveal_timeout
        assert channel.settle_timeout == channel_container.settle_timeout

