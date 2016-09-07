# -*- coding: utf8 -*-
from __future__ import print_function

from gevent import monkey
monkey.patch_all()

import signal
import gevent
import click
import json
from ethereum import slogging
from raiden.console import ConsoleTools
from raiden.app import app as orig_app
from raiden.app import options

log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


@click.option(
        '--scenario',
        help='path to scenario.json',
        type=click.File()
        )
@options
@click.command()
@click.pass_context
def run(ctx, scenario, **kwargs):
    ctx.params.pop('scenario')
    app = ctx.invoke(orig_app)
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
        for token in tokens:
            # skip tokens/assets that we're not part of
            if not app.raiden.address.encode('hex') in token['channels']:
                continue

            # allow for prefunded tokens
            if 'token_address' in token:
                token_address = token['token_address']
            else:
                token_address = tools.create_token()

            transfers_with_amount = token['transfers_with_amount']
            for node in token['channels']:
                # FIXME: in order to do bidirectional channels, only one side
                # (i.e. only token['channels'][0]) should
                # open; others should join by calling
                # raiden.api.deposit, AFTER the channel came alive!
                if node != app.raiden.address.encode('hex'):
                    tools.register_asset(token_address)
                    channel = tools.open_channel_with_funding(
                        token_address, node, 1000)
                    transfers_by_channel[channel] = int(transfers_with_amount[node])

        def transfer(token_address, amount_per_transfer, total_transfers, channel):
            peer = channel.partner(app.raiden.address)

            def transfer_():
                for _ in xrange(total_transfers):
                    app.raiden.transfer(token_address, amount_per_transfer, peer)

            return gevent.spawn(
                transfer, amount_per_transfer, peer
            )

        greenlets = []
        for channel, amount in transfers_by_channel.items():
            greenlets.append(transfer(token_address, 1, amount, channel))

        gevent.joinall(greenlets)

    else:
        # wait for interrupt
        event = gevent.event.Event()
        gevent.signal(signal.SIGQUIT, event.set)
        gevent.signal(signal.SIGTERM, event.set)
        gevent.signal(signal.SIGINT, event.set)
        event.wait()

    app.stop()


if __name__ == '__main__':
    run()
