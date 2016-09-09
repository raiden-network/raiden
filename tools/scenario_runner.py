#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import signal
import json

import click
import gevent
from gevent import monkey
from ethereum import slogging

from raiden.console import ConsoleTools
from raiden.app import app as orig_app
from raiden.app import options


monkey.patch_all()
log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


@click.option(  # noqa
    '--scenario',
    help='path to scenario.json',
    type=click.File()
)
@options
@click.command()
@click.pass_context  # pylint: disable=too-many-locals
def run(ctx, scenario, **kwargs):  # pylint: disable=unused-argument
    ctx.params.pop('scenario')
    app = ctx.invoke(orig_app, **kwargs)
    if scenario:
        script = json.load(scenario)

        tools = ConsoleTools(
            app.raiden,
            app.discovery,
            app.config['settle_timeout'],
            app.config['reveal_timeout'],
        )

        transfers_by_channel = {}

        tokens = script['assets']
        token_address = None
        peer = None
        for token in tokens:
            # skip tokens/assets that we're not part of
            if not app.raiden.address.encode('hex') in token['channels']:
                continue

            # allow for prefunded tokens
            if 'token_address' in token:
                token_address = token['token_address']
            else:
                token_address = tools.create_token()

            nodes = token['channels']
            if not app.raiden.address.encode('hex') in nodes:
                continue

            transfers_with_amount = token['transfers_with_amount']

            # FIXME: in order to do bidirectional channels, only one side
            # (i.e. only token['channels'][0]) should
            # open; others should join by calling
            # raiden.api.deposit, AFTER the channel came alive!

            # FIXME: leave unidirectional for now

            if app.raiden.address.encode('hex') == nodes[0]:
                tools.register_asset(token_address)
                log.info("opening channel for {}".format(token_address))
                channel = tools.open_channel_with_funding(
                    token_address, nodes[1], 1000)
                log.info("new channel is {}".format(channel))
                #transfers_by_channel[channel] = int(transfers_with_amount[nodes[1]])
                transfers_by_channel[channel] = 1
                peer = nodes[1]
            else:
                peer = nodes[0]
                continue

        def transfer(token_address, amount_per_transfer, total_transfers, channel):
            if channel is None:
                return

            peer = channel.partner(app.raiden.address)

            def transfer_():
                log.info("making {} transfers".format(total_transfers))
                for _ in xrange(total_transfers):
                    app.raiden.transfer(token_address, amount_per_transfer, peer)

            return gevent.spawn(transfer_)

        log.info("transfers_by_channel: {}".format(transfers_by_channel))

        greenlets = []
        for channel, amount in transfers_by_channel.items():
            log.info("adding greenlet for token_address {} for channel {}".format(
                token_address, channel))
            greenlet = transfer(token_address, 1, amount, channel)
            if greenlet is not None:
                greenlets.append(greenlet)

        log.info("join all")
        gevent.joinall(greenlets)

        log.info("will wait for signals")

        event = gevent.event.Event()
        gevent.signal(signal.SIGQUIT, event.set)
        gevent.signal(signal.SIGTERM, event.set)
        gevent.signal(signal.SIGINT, event.set)
        event.wait()

        log.info("stats: {}".format(tools.channel_stats_for(token_address, peer)))

    else:
        # wait for interrupt
        event = gevent.event.Event()
        gevent.signal(signal.SIGQUIT, event.set)
        gevent.signal(signal.SIGTERM, event.set)
        gevent.signal(signal.SIGINT, event.set)
        event.wait()

    app.stop()


if __name__ == '__main__':
    run()  # pylint: disable=no-value-for-parameter
