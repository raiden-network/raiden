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

from ethereum.utils import decode_hex
from raiden.console import ConsoleTools
from raiden.app import App
from raiden.network.rpc.client import BlockChainService
from raiden.network.discovery import ContractDiscovery
from raiden.utils import split_endpoint


monkey.patch_all()
log = slogging.get_logger(__name__)  # pylint: disable=invalid-name


@click.option(  # noqa
    '--privatekey',
    type=str,
)
@click.option(  # noqa
    '--registry-contract-address',
    type=str,
)
@click.option(  # noqa
    '--discovery-contract-address',
    type=str,
)
@click.option(  # noqa
    '--listen-address',
    type=str,
)
@click.option(  # noqa
    '--logging',
    default=':INFO',
    type=str,
)
@click.option(  # noqa
    '--logfile',
    default=None,
    type=str
)
@click.option(  # noqa
    '--scenario',
    type=click.File()
)
@click.option(  # noqa
    '--stage-prefix',
    type=str
)
@click.option(  # noqa
    '--results-filename',
    type=str
)
@click.command()
def run(privatekey,
        registry_contract_address,
        discovery_contract_address,
        listen_address,
        logging,
        logfile,
        scenario,
        stage_prefix,
        results_filename):  # pylint: disable=unused-argument

    # TODO: only enabled logging on "initiators"
    slogging.configure(logging, log_file=logfile)

    (listen_host, listen_port) = split_endpoint(listen_address)

    config = App.default_config.copy()
    config['host'] = listen_host
    config['port'] = listen_port
    config['privatekey_hex'] = privatekey

    blockchain_service = BlockChainService(
        decode_hex(privatekey),
        decode_hex(registry_contract_address),
        host="127.0.0.1",
        port="8545",
    )

    discovery = ContractDiscovery(
        blockchain_service,
        decode_hex(discovery_contract_address)
    )

    app = App(config, blockchain_service, discovery)

    app.discovery.register(
        app.raiden.address,
        listen_host,
        listen_port,
    )

    app.raiden.register_registry(app.raiden.chain.default_registry.address)

    if scenario:
        script = json.load(scenario)

        tools = ConsoleTools(
            app.raiden,
            app.discovery,
            app.config['settle_timeout'],
            app.config['reveal_timeout'],
        )

        transfers_by_peer = {}

        tokens = script['tokens']
        token_address = None
        peer = None
        our_node = app.raiden.address.encode('hex')
        log.warning("our address is {}".format(our_node))
        for token in tokens:
            # skip tokens that we're not part of
            nodes = token['channels']
            if our_node not in nodes:
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
                gevent.sleep(5)

            log.warning("All nodes are online")

            if our_node != nodes[-1]:
                our_index = nodes.index(our_node)
                peer = nodes[our_index + 1]

                tools.register_token(token_address)
                amount = transfers_with_amount[nodes[-1]]

                while True:
                    try:
                        app.discovery.get(peer.decode('hex'))
                        break
                    except KeyError:
                        log.warning("Error: peer {} not found in discovery".format(peer))
                        time.sleep(random.randrange(30))

                while True:
                    try:
                        log.warning("Opening channel with {} for {}".format(peer, token_address))
                        app.raiden.api.open(token_address, peer)
                        break
                    except KeyError:
                        log.warning("Error: could not open channel with {}".format(peer))
                        time.sleep(random.randrange(30))

                while True:
                    try:
                        log.warning("Funding channel with {} for {}".format(peer, token_address))
                        app.raiden.api.deposit(token_address, peer, amount)
                        break
                    except Exception:
                        log.warning("Error: could not deposit {} for {}".format(amount, peer))
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

        transfer_results = {'total_time': 0, 'timestamps': []}

        def transfer(token_address, amount_per_transfer, total_transfers, peer, is_async):
            def transfer_():
                log.warning("Making {} transfers to {}".format(total_transfers, peer))
                initial_time = time.time()
                times = [0] * total_transfers
                for index in xrange(total_transfers):
                    app.raiden.api.transfer(
                        token_address.decode('hex'),
                        amount_per_transfer,
                        peer,
                    )
                    times[index] = time.time()

                transfer_results['total_time'] = time.time() - initial_time
                transfer_results['timestamps'] = times

                log.warning("Making {} transfers took {}".format(
                    total_transfers, transfer_results['total_time']))
                log.warning("Times: {}".format(times))

            if is_async:
                return gevent.spawn(transfer_)
            else:
                transfer_()

        # If sending to multiple targets, do it asynchronously, otherwise
        # keep it simple and just send to the single target on my thread.
        if len(transfers_by_peer) > 1:
            greenlets = []
            for peer_, amount in transfers_by_peer.items():
                greenlet = transfer(token_address, 1, amount, peer_, True)
                if greenlet is not None:
                    greenlets.append(greenlet)

            gevent.joinall(greenlets)

        elif len(transfers_by_peer) == 1:
            for peer_, amount in transfers_by_peer.items():
                transfer(token_address, 1, amount, peer_, False)

        log.warning("Waiting for termination")

        open('{}.stage2'.format(stage_prefix), 'a').close()
        log.warning("Waiting for transfers to finish, will write results...")
        event = gevent.event.Event()
        gevent.signal(signal.SIGUSR2, event.set)
        event.wait()

        results = tools.channel_stats_for(token_address, peer)
        if transfer_results['total_time'] != 0:
            results['total_time'] = transfer_results['total_time']
        if len(transfer_results['timestamps']) > 0:
            results['timestamps'] = transfer_results['timestamps']
        results['channel'] = repr(results['channel'])  # FIXME

        log.warning("Results: {}".format(results))

        with open(results_filename, 'w') as fp:
            json.dump(results, fp, indent=2)

        open('{}.stage3'.format(stage_prefix), 'a').close()
        event = gevent.event.Event()
        gevent.signal(signal.SIGQUIT, event.set)
        gevent.signal(signal.SIGTERM, event.set)
        gevent.signal(signal.SIGINT, event.set)
        event.wait()

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
