# -*- coding: utf-8 -*-
from collections import deque

import gevent
from gevent.queue import Queue
from gevent.lock import Semaphore
from ethereum import slogging
import click

from raiden.ui.cli import (
    options,
    app,
    split_endpoint,
    socket_factory,
    signal,
    APIServer,
    RestAPI,
    ADDRESS_TYPE)
from raiden.tasks import REMOVE_CALLBACK
from raiden.utils import pex
from raiden.transfer.state import CHANNEL_STATE_OPENED
from raiden.api.python import RaidenAPI

log = slogging.getLogger(__name__)

# number of transfer's we will check for duplicates
TRANSFER_MEMORY = 256


class EchoNode(object):

    def __init__(self, api, token_address):
        assert isinstance(api, RaidenAPI)

        self.api = api
        self.token_address = token_address

        existing_channels = self.api.get_channel_list(self.token_address)
        open_channels = [
            channel for channel in existing_channels if channel.state == CHANNEL_STATE_OPENED
        ]
        if len(open_channels) == 0:
            token = self.api.raiden.chain.token(self.token_address)
            if not token.balance_of(self.api.raiden.address) > 0:
                raise ValueError('not enough funds for echo node %s for token %s' % (
                    pex(self.api.raiden.address),
                    pex(self.token_address),
                ))
            self.last_poll_block = self.api.raiden.get_block_number()
            self.api.connect_token_network(
                self.token_address,
                token.balance_of(self.api.raiden.address),
                initial_channel_target=10,
                joinable_funds_target=.5,
            )
        else:
            self.last_poll_block = min(
                channel.external_state.opened_block for channel in open_channels
            )

        self.received_transfers = Queue()
        self.stop_signal = None  # used to signal REMOVE_CALLBACK and stop echo_workers
        self.greenlets = list()
        self.lock = Semaphore()
        self.handled_transfers = deque(list(), TRANSFER_MEMORY)
        # register ourselves with the raiden alarm task
        self.api.raiden.alarm.register_callback(self.echo_node_alarm_callback)

    def echo_node_alarm_callback(self, block_number):
        """ This can be registered with the raiden AlarmTask.
        If `EchoNode.stop()` is called, it will give the return signal to be removed from
        the AlarmTask callbacks.
        """
        log.DEV('echo_node callback', block_number=block_number)
        if self.stop_signal is not None:
            return REMOVE_CALLBACK
        else:
            self.greenlets.append(gevent.spawn(self.poll_all_received_events))
            return True

    def poll_all_received_events(self):
        """ This will be triggered once for each `echo_node_alarm_callback`.
        It polls all channels for `EventTransferReceivedSuccess` events,
        adds all new events to the `self.received_transfers` queue and
        spawns an `self.echo_node_worker`, if there were new events. """

        with self.lock:
            channels = self.api.get_channel_list(token_address=self.token_address)
            received_transfers = list()
            for channel in channels:
                channel_events = self.api.get_channel_events(
                    channel.channel_address,
                    self.last_poll_block
                )
                received_transfers.extend([
                    event for event in channel_events
                    if event['_event_type'] == 'EventTransferReceivedSuccess'
                ])
            if received_transfers:
                self.last_poll_block = max(
                    event['block_number']
                    for event in received_transfers
                ) + 1
            for transfer in received_transfers:
                self.received_transfers.put(transfer)
            if len(received_transfers):
                self.greenlets.append(gevent.spawn(self.echo_worker))

    def echo_worker(self):
        """ The `echo_worker` works through the `self.received_transfers` queue and spawns
        `self.on_transfer` greenlets for all transfers. """
        while self.stop_signal is None and self.received_transfers.qsize() > 0:
            transfer = self.received_transfers.get()
            self.greenlets.append(gevent.spawn(self.on_transfer, transfer))

    def on_transfer(self, transfer):
        """ This checks for duplicated transfer events and handles the echo logic, as described in
        https://github.com/raiden-network/raiden/issues/651:

            - for transfers with an amount that satisfies `amount % 3 == 0`, it sends a transfer
            with an amount of `amount - 1` back to the initiator
            - for transfers with a "lucky number" amount `amount == 7` it does not send anything
            back immediately -- after having received "lucky number transfers" from 7 different
            addresses it sends a transfer with `amount = 49` to one randomly chosen one
            (from the 7 lucky addresses) [NOT YET IMPLEMENTED]
            - for all other transfers it sends a transfer with the same `amount` back to the
            initiator """
        echo_amount = 0
        if transfer in self.handled_transfers:
            log.DEV(
                'duplicate transfer received',
                initiator=pex(transfer['initiator']),
                amount=transfer['amount'],
                identifier=transfer['identifier']
            )
        elif transfer['amount'] % 3 == 0:
            log.DEV(
                'minus one transfer received',
                initiator=pex(transfer['initiator']),
                amount=transfer['amount'],
                identifier=transfer['identifier']
            )
            echo_amount = transfer['amount'] - 1
        elif transfer['amount'] == 7:
            # FIXME: the lottery transfers are not yet implemented.
            # the idea is, to collect 7 transfers with amount == 7 and randomly chose one initator,
            # that will receive 49 tokens back
            log.DEV(
                'not implemented: lucky number transfer received. handling like regular transfer',
                initiator=pex(transfer['initiator']),
                amount=transfer['amount'],
                identifier=transfer['identifier']
            )
            echo_amount = transfer['amount']
        else:
            log.DEV(
                'echo transfer received',
                initiator=pex(transfer['initiator']),
                amount=transfer['amount'],
                identifier=transfer['identifier']
            )
            echo_amount = transfer['amount']
        if echo_amount:
            log.DEV(
                'sending echo transfer',
                target=pex(transfer['initiator']),
                amount=echo_amount,
                orig_identifier=transfer['identifier'],
                echo_identifier=transfer['identifier'] + echo_amount,
                token_address=pex(self.token_address),
            )

            self.api.transfer_and_wait(
                self.token_address,
                echo_amount,
                transfer['initiator'],
                identifier=transfer['identifier'] + echo_amount
            )
            self.handled_transfers.append(transfer)

    def stop(self):
        self.stop_signal = True
        gevent.wait(self.greenlets)


@click.group(invoke_without_command=True)
@options
@click.option("--token-address", type=ADDRESS_TYPE, required=True)
@click.pass_context
def runner(ctx, **kwargs):
    """ Start a raiden Echo Node that will send received transfers back to the initiator. """
    # This is largely a copy&paste job from `raiden.ui.cli::run`, with the difference that
    # an `EchoNode` is instantiated from the App's `RaidenAPI`.
    slogging.configure(kwargs['logging'], log_file=kwargs['logfile'])

    token_address = kwargs.pop('token_address')

    (listen_host, listen_port) = split_endpoint(kwargs['listen_address'])
    with socket_factory(listen_host, listen_port) as mapped_socket:
        kwargs['mapped_socket'] = mapped_socket

        app_ = ctx.invoke(app, **kwargs)

        domain_list = []
        if kwargs['rpccorsdomain']:
            if ',' in kwargs['rpccorsdomain']:
                for domain in kwargs['rpccorsdomain'].split(','):
                    domain_list.append(str(domain))
            else:
                domain_list.append(str(kwargs['rpccorsdomain']))

        raiden_api = RaidenAPI(app_.raiden)
        if ctx.params['rpc']:
            rest_api = RestAPI(raiden_api)
            api_server = APIServer(
                rest_api,
                cors_domain_list=domain_list,
                web_ui=ctx.params['web_ui'],
            )
            (api_host, api_port) = split_endpoint(kwargs["api_address"])
            api_server.start(api_host, api_port)

            print(
                "The Raiden API RPC server is now running at http://{}:{}/.\n\n"
                "See the Raiden documentation for all available endpoints at\n"
                "https://github.com/raiden-network/raiden/blob/master"
                "/docs/Rest-Api.rst".format(
                    api_host,
                    api_port,
                )
            )

        # This will install the EchoNode callback in the alarm task:
        echo = EchoNode(raiden_api, token_address)

        event = gevent.event.Event()
        gevent.signal(signal.SIGQUIT, event.set)
        gevent.signal(signal.SIGTERM, event.set)
        gevent.signal(signal.SIGINT, event.set)
        event.wait()

        # This will remove the EchoNode callback from the alarm task:
        echo.stop()

        try:
            api_server.stop()
        except NameError:
            pass
    app_.stop(leave_channels=False)


if __name__ == '__main__':
    runner()
