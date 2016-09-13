#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import signal
import json

import click
import gevent
from gevent import monkey
import time
import random
from ethereum import slogging

from raiden.console import ConsoleTools
from raiden.app import app as orig_app
from raiden.app import options
from raiden.utils import split_endpoint


monkey.patch_all()
log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


@click.option(  # noqa
    '--external_listen_address',
    default='',
    type=str,
)
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
def run(ctx, external_listen_address, scenario, stage_prefix, **kwargs):  # pylint: disable=unused-argument
    if not external_listen_address:
        external_listen_address = kwargs['listen_address']

    ctx.params.pop('external_listen_address')
    ctx.params.pop('scenario')
    ctx.params.pop('stage_prefix')
    app = ctx.invoke(orig_app, **kwargs)

    app.discovery.register(
        app.raiden.address,
        *split_endpoint(external_listen_address)
    )

    app.raiden.register_registry(app.raiden.chain.default_registry)

    if scenario:
        script = json.load(scenario)

        tools = ConsoleTools(
            app.raiden,
            app.discovery,
            app.config['settle_timeout'],
            app.config['reveal_timeout'],
        )

        transfers_by_peer = {}

        tokens = script['assets']
        token_address = None
        peer = None
        our_node = app.raiden.address.encode('hex')
        log.warning("our address is {}".format(our_node))
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


            log.warning("Waiting for all nodes to come online")

            while not all(tools.ping(node) for node in nodes if node != our_node):
                gevent.sleep(1)

            log.warning("All nodes are online")

            if our_node != nodes[-1]:
                our_index = nodes.index(our_node)
                peer = nodes[our_index + 1]

                channel_manager = tools.register_asset(token_address)
                amount = transfers_with_amount[nodes[-1]]

                log.warning("Opening channel with {} for {}".format(peer, token_address))

                # opening channels, like life, is sometimes hard, but don't lose faith...
                while True:
                    try:
                        channel = tools.open_channel_with_funding(token_address, peer, amount)
                        break
                    except KeyError:
                        time.sleep(random.randrange(30))

                if our_index == 0:
                    last_node = nodes[-1]
                    transfers_by_peer[last_node] = int(amount)
            else:
                peer = nodes[-2]

        if stage_prefix is not None:
            open('{}.stage1'.format(stage_prefix), 'a').close()
            log.warning("Done with initialization, waiting to continue...")
            event = gevent.event.Event()
            gevent.signal(signal.SIGUSR2, event.set)
            event.wait()

        def transfer(token_address, amount_per_transfer, total_transfers, peer, is_async):
            def transfer_():
                log.warning("Making {} transfers to {}".format(total_transfers, peer))
                initial_time = time.time()
                for _ in xrange(total_transfers):
                    app.raiden.api.transfer(
                        token_address.decode('hex'),
                        amount_per_transfer,
                        peer,
                    )
                log.warning("Making {} transfers took {}".format(
                    total_transfers, time.time() - initial_time))

            if is_async:
                return gevent.spawn(transfer_)
            else:
                transfer_()

        # If sending to multiple targets, do it asynchronously, otherwise
        # keep it simple and just send to the single target on my thread.
        if len(transfers_by_peer) > 1:
            greenlets = []
            for peer, amount in transfers_by_peer.items():
                greenlet = transfer(token_address, 1, amount, peer, True)
                if greenlet is not None:
                    greenlets.append(greenlet)

            gevent.joinall(greenlets)

        elif len(transfers_by_peer) == 1:
            for peer, amount in transfers_by_peer.items():
                transfer(token_address, 1, amount, peer, False)

        log.warning("Waiting for termination")

        open('{}.stage2'.format(stage_prefix), 'a').close()
        event = gevent.event.Event()
        gevent.signal(signal.SIGQUIT, event.set)
        gevent.signal(signal.SIGTERM, event.set)
        gevent.signal(signal.SIGINT, event.set)
        event.wait()

        log.warning("Results: {}".format(tools.channel_stats_for(token_address, peer)))

    else:
        log.warning("No scenario file supplied, doing nothing!")

        open('{}.stage2'.format(stage_prefix), 'a').close()
        event = gevent.event.Event()
        gevent.signal(signal.SIGQUIT, event.set)
        gevent.signal(signal.SIGTERM, event.set)
        gevent.signal(signal.SIGINT, event.set)
        event.wait()

    app.stop()


if __name__ == '__main__':
    run()  # pylint: disable=no-value-for-parameter
