# -*- coding: utf-8 -*-
from gevent import monkey, Greenlet, sleep
monkey.patch_all()

import requests
from raiden.api.rest import RestAPI, APIServer, app
from raiden.channel import Channel, ChannelEndState, ChannelExternalState


# TODO: this is ripped from unit/test_channel.py. Abstract it out somewhere.
class NettingChannelMock(object):
    # pylint: disable=no-self-use
    def opened(self):
        return 1

    def closed(self):
        return 0

    def settled(self):
        return 0


def return_stuff():
    our_address = '0x2a65aca4d5fc5b5c859090a6c34d164135398226'
    partner_address = '0xea674fdde714fd979de3edf0f56aa9716b898ec8'
    token_address = '0x61c808d82a3ac53231750dadc13c777b59310bd9'
    our_balance = 10
    partner_balance = 10
    reveal_timeout = 20
    settle_timeout = 800
    our_state = ChannelEndState(our_address, our_balance, 1)
    partner_state = ChannelEndState(partner_address, partner_balance, 1)

    block_alarm = list()
    channel_for_hashlock = list()
    netting_channel = NettingChannelMock()
    external_state = ChannelExternalState(
        block_alarm.append,
        lambda *args: channel_for_hashlock.append(args),
        lambda: 1,
        netting_channel,
    )

    return Channel(
        our_state,
        partner_state,
        external_state,
        token_address,
        reveal_timeout,
        settle_timeout,
    )


def test_api_query_channels(monkeypatch, raiden_service):
    monkeypatch.setattr(
        raiden_service.api,
        'get_channel_list',
        return_stuff
    )
    rest_api = RestAPI(raiden_service)
    api_server = APIServer(rest_api)

    app.config['TESTING'] = True
    g = Greenlet.spawn(api_server.run, 5001, debug=True)
    print requests.get('http://localhost:5001/api/1/channels')
    sleep(1)
    g.kill(block=True, timeout=10)
