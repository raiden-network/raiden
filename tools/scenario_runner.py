#!/usr/bin/env python
from binascii import hexlify
import signal
import json
import time
import random

import click
import gevent
import structlog

from eth_utils import decode_hex

from raiden.app import App
from raiden.api.python import RaidenAPI
from raiden.network.blockchain_service import BlockChainService
from raiden.network.discovery import ContractDiscovery
from raiden.network.protocol import NODE_NETWORK_REACHABLE
from raiden.network.protocol import UDPTransport
from raiden.network.rpc.client import JSONRPCClient
from raiden.network.throttle import TokenBucket
from raiden.ui.console import ConsoleTools
from raiden.utils import split_endpoint

gevent.monkey.patch_all()
log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


@click.option(  # noqa
    '--privatekey',
    type=str,
)
@click.option(  # noqa
    '--registry-contract-address',
    type=str,
)
@click.option(  # noqa
    '--secret-registry-contract-address',
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
    '--structlog',
    default=':INFO',
    type=str,
)
@click.option(  # noqa
    '--logfile',
    default=None,
    type=str,
)
@click.option(  # noqa
    '--scenario',
    type=click.File(),
)
@click.option(  # noqa
    '--stage-prefix',
    type=str,
)
@click.option(  # noqa
    '--results-filename',
    type=str,
)
@click.command()
def run(
        privatekey,
        registry_contract_address,
        secret_registry_contract_address,
        discovery_contract_address,
        listen_address,
        structlog,
        logfile,
        scenario,
        stage_prefix,
):  # pylint: disable=unused-argument

    # TODO: only enabled structlog on "initiators"
    structlog.configure(structlog, log_file=logfile)

    (listen_host, listen_port) = split_endpoint(listen_address)

    config = App.DEFAULT_CONFIG.copy()
    config['host'] = listen_host
    config['port'] = listen_port
    config['privatekey_hex'] = privatekey

    privatekey_bin = decode_hex(privatekey)

    rpc_client = JSONRPCClient(
        '127.0.0.1',
        8545,
        privatekey_bin,
    )

    blockchain_service = BlockChainService(privatekey_bin, rpc_client)

    discovery = ContractDiscovery(
        blockchain_service,
        decode_hex(discovery_contract_address),
    )

    registry = blockchain_service.token_network_registry(
        registry_contract_address,
    )

    secret_registry = blockchain_service.secret_registry(
        secret_registry_contract_address,
    )

    throttle_policy = TokenBucket(
        config['protocol']['throttle_capacity'],
        config['protocol']['throttle_fill_rate'],
    )

    transport = UDPTransport(
        discovery=discovery,
        udpsocket=gevent.server._udp_socket((listen_host, listen_port)),
        throttle_policy=throttle_policy,
        config=config['protocol'],
    )

    app = App(
        config=config,
        chain=blockchain_service,
        query_start_block=0,
        default_registry=registry,
        default_secret_registry=secret_registry,
        transport=transport,
        discovery=discovery,
    )

    app.discovery.register(
        app.raiden.address,
        listen_host,
        listen_port,
    )

    from_block = 0
    app.raiden.install_all_blockchain_filters(
        app.raiden.default_registry,
        app.raiden.default_secret_registry,
        from_block,
    )

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
        our_node = hexlify(app.raiden.address)
        log.warning('our address is {}'.format(our_node))
        for token in tokens:
            # skip tokens that we're not part of
            nodes = token['channels']
            if our_node not in nodes:
                continue

            partner_nodes = [
                node
                for node in nodes
                if node != our_node
            ]

            # allow for prefunded tokens
            if 'token_address' in token:
                token_address = token['token_address']
            else:
                token_address = tools.create_token(registry_contract_address)

            transfers_with_amount = token['transfers_with_amount']

            # FIXME: in order to do bidirectional channels, only one side
            # (i.e. only token['channels'][0]) should
            # open; others should join by calling
            # raiden.api.deposit, AFTER the channel came alive!

            # NOTE: leaving unidirectional for now because it most
            #       probably will get to higher throughput

            log.warning('Waiting for all nodes to come online')

            api = RaidenAPI(app.raiden)

            for node in partner_nodes:
                api.start_health_check_for(node)

            while True:
                all_reachable = all(
                    api.get_node_network_state(node) == NODE_NETWORK_REACHABLE
                    for node in partner_nodes
                )

                if all_reachable:
                    break

                gevent.sleep(5)

            log.warning('All nodes are online')

            if our_node != nodes[-1]:
                our_index = nodes.index(our_node)
                peer = nodes[our_index + 1]

                tools.token_network_register(app.raiden.default_registry.address, token_address)
                amount = transfers_with_amount[nodes[-1]]

                while True:
                    try:
                        app.discovery.get(peer.decode('hex'))
                        break
                    except KeyError:
                        log.warning('Error: peer {} not found in discovery'.format(peer))
                        time.sleep(random.randrange(30))

                while True:
                    try:
                        log.warning('Opening channel with {} for {}'.format(peer, token_address))
                        api.channel_open(app.raiden.default_registry.address, token_address, peer)
                        break
                    except KeyError:
                        log.warning('Error: could not open channel with {}'.format(peer))
                        time.sleep(random.randrange(30))

                while True:
                    try:
                        log.warning('Funding channel with {} for {}'.format(peer, token_address))
                        api.channel_deposit(
                            app.raiden.default_registry.address,
                            token_address,
                            peer,
                            amount,
                        )
                        break
                    except Exception:
                        log.warning('Error: could not deposit {} for {}'.format(amount, peer))
                        time.sleep(random.randrange(30))

                if our_index == 0:
                    last_node = nodes[-1]
                    transfers_by_peer[last_node] = int(amount)

        if stage_prefix is not None:
            open('{}.stage1'.format(stage_prefix), 'a').close()
            log.warning('Done with initialization, waiting to continue...')
            event = gevent.event.Event()
            gevent.signal(signal.SIGUSR2, event.set)
            event.wait()

        transfer_results = {'total_time': 0, 'timestamps': []}

        def transfer(token_address, amount_per_transfer, total_transfers, peer, is_async):
            def transfer_():
                log.warning('Making {} transfers to {}'.format(total_transfers, peer))
                initial_time = time.time()
                times = [0] * total_transfers
                for index in range(total_transfers):
                    RaidenAPI(app.raiden).transfer(
                        app.raiden.default_registry.address,
                        token_address.decode('hex'),
                        amount_per_transfer,
                        peer,
                    )
                    times[index] = time.time()

                transfer_results['total_time'] = time.time() - initial_time
                transfer_results['timestamps'] = times

                log.warning('Making {} transfers took {}'.format(
                    total_transfers, transfer_results['total_time']))
                log.warning('Times: {}'.format(times))

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

        log.warning('Waiting for termination')

        open('{}.stage2'.format(stage_prefix), 'a').close()
        log.warning('Waiting for transfers to finish, will write results...')
        event = gevent.event.Event()
        gevent.signal(signal.SIGUSR2, event.set)
        event.wait()

        open('{}.stage3'.format(stage_prefix), 'a').close()
        event = gevent.event.Event()
        gevent.signal(signal.SIGQUIT, event.set)
        gevent.signal(signal.SIGTERM, event.set)
        gevent.signal(signal.SIGINT, event.set)
        event.wait()

    else:
        log.warning('No scenario file supplied, doing nothing!')

        open('{}.stage2'.format(stage_prefix), 'a').close()
        event = gevent.event.Event()
        gevent.signal(signal.SIGQUIT, event.set)
        gevent.signal(signal.SIGTERM, event.set)
        gevent.signal(signal.SIGINT, event.set)
        event.wait()

    app.stop()


if __name__ == '__main__':
    run()  # pylint: disable=no-value-for-parameter
