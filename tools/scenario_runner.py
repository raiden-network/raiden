#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import signal
import json

import click
import gevent
from gevent import monkey
import time
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
@click.option(  # noqa
    '--stage_prefix',
    help='prefix of temporary stage files',
    type=str
)
@options
@click.command()
@click.pass_context  # pylint: disable=too-many-locals
def run(ctx, scenario, stage_prefix, **kwargs):  # pylint: disable=unused-argument
    ctx.params.pop('scenario')
    ctx.params.pop('stage_prefix')
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
        our_node = app.raiden.address.encode('hex')
        for token in tokens:
            # skip tokens/assets that we're not part of
            nodes = token['channels']
            if not our_node in nodes:
                continue

            # allow for prefunded tokens
            if 'token_address' in token:
                token_address = token['token_address']
            else:
                token_address = tools.create_token()

            transfers_with_amount = token['transfers_with_amount']

            # FIXME: in order to do bidirectional channels, only one side
            # (i.e. only token['channels'][0]) should
            # open; others should join by calling
            # raiden.api.deposit, AFTER the channel came alive!

            # NOTE: leaving unidirectional for now because it most
            #       probably will get to higher throughput


            log.info("Waiting for all nodes to come online")

            while not all(tools.ping(node) for node in nodes if node != our_node):
                gevent.sleep(1)

            log.info("All nodes are online")

            # FIXME: attached to sending from first... bad!
            if our_node == nodes[0]:
                peer = nodes[1]

                channel_manager = tools.register_asset(token_address)

                amount = transfers_with_amount[nodes[0]]
                log.info("Opening channel for {}".format(token_address))
                channel = tools.open_channel_with_funding(token_address, peer, amount)
                transfers_by_channel[channel] = int(transfers_with_amount[nodes[1]])
            else:
                peer = nodes[0]

        if stage_prefix is not None:
            open('{}.stage1'.format(stage_prefix), 'a').close()
            log.info("Done with initialization, waiting to continue...")
            event = gevent.event.Event()
            gevent.signal(signal.SIGUSR2, event.set)
            event.wait()

        def transfer(token_address, amount_per_transfer, total_transfers, channel, is_async):
            if channel is None:
                return

            peer = channel.partner(app.raiden.address).encode('hex')

            def transfer_(peer_):
                log.info("Making {} transfers to {}".format(total_transfers, peer_))
                initial_time = time.time()
                for _ in xrange(total_transfers):
                    app.raiden.api.transfer(
                        token_address.decode('hex'),
                        amount_per_transfer,
                        peer_,
                    )
                log.info("Making {} transfers took {}".format(
                    total_transfers, time.time() - initial_time))

            if is_async:
                return gevent.spawn(transfer_, peer)
            else:
                transfer_(peer)

        # If sending to multiple targets, do it asynchronously, otherwise
        # keep it simple and just send to the single target on my thread.
        if len(transfers_by_channel) > 1:
            greenlets = []
            for channel, amount in transfers_by_channel.items():
                greenlet = transfer(token_address, 1, amount, channel, True)
                if greenlet is not None:
                    greenlets.append(greenlet)

            gevent.joinall(greenlets)

        elif len(transfers_by_channel) == 1:
            for channel, amount in transfers_by_channel.items():
                transfer(token_address, 1, amount, channel, False)

        log.info("Waiting for termination")

        event = gevent.event.Event()
        gevent.signal(signal.SIGQUIT, event.set)
        gevent.signal(signal.SIGTERM, event.set)
        gevent.signal(signal.SIGINT, event.set)
        event.wait()

        log.info("Results: {}".format(tools.channel_stats_for(token_address, peer)))

    else:
        log.info("No scenario file supplied, doing nothing!")
        event = gevent.event.Event()
        gevent.signal(signal.SIGQUIT, event.set)
        gevent.signal(signal.SIGTERM, event.set)
        gevent.signal(signal.SIGINT, event.set)
        event.wait()

    app.stop()


if __name__ == '__main__':
    run()  # pylint: disable=no-value-for-parameter
