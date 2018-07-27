from collections import deque
import random

import gevent
from gevent.queue import Queue
from gevent.lock import BoundedSemaphore
from gevent.event import Event
from gevent.timeout import Timeout
import structlog

from raiden.api.python import RaidenAPI
from raiden.tasks import REMOVE_CALLBACK
from raiden.transfer import channel
from raiden.transfer.state import CHANNEL_STATE_OPENED
from raiden.utils import pex


log = structlog.get_logger(__name__)

# number of transfers we will check for duplicates
TRANSFER_MEMORY = 4096


class EchoNode:

    def __init__(self, api, token_address):
        assert isinstance(api, RaidenAPI)
        self.ready = Event()

        self.api = api
        self.token_address = token_address

        existing_channels = self.api.get_channel_list(
            api.raiden.default_registry.address,
            self.token_address,
        )

        open_channels = [
            channel_state
            for channel_state in existing_channels
            if channel.get_status(channel_state) == CHANNEL_STATE_OPENED
        ]

        if len(open_channels) == 0:
            token = self.api.raiden.chain.token(self.token_address)
            if not token.balance_of(self.api.raiden.address) > 0:
                raise ValueError('not enough funds for echo node %s for token %s' % (
                    pex(self.api.raiden.address),
                    pex(self.token_address),
                ))
            self.api.token_network_connect(
                self.api.raiden.default_registry.address,
                self.token_address,
                token.balance_of(self.api.raiden.address),
                initial_channel_target=10,
                joinable_funds_target=.5,
            )

        self.last_poll_block = self.api.raiden.get_block_number()
        self.received_transfers = Queue()
        self.stop_signal = None  # used to signal REMOVE_CALLBACK and stop echo_workers
        self.greenlets = list()
        self.lock = BoundedSemaphore()
        self.seen_transfers = deque(list(), TRANSFER_MEMORY)
        self.num_handled_transfers = 0
        self.lottery_pool = Queue()
        # register ourselves with the raiden alarm task
        self.api.raiden.alarm.register_callback(self.echo_node_alarm_callback)
        self.echo_worker_greenlet = gevent.spawn(self.echo_worker)
        log.info('Echo node started')

    def echo_node_alarm_callback(self, block_number, chain_id):
        """ This can be registered with the raiden AlarmTask.
        If `EchoNode.stop()` is called, it will give the return signal to be removed from
        the AlarmTask callbacks.
        """
        if not self.ready.is_set():
            self.ready.set()
        log.debug('echo_node callback', block_number=block_number)
        if self.stop_signal is not None:
            return REMOVE_CALLBACK
        else:
            self.greenlets.append(gevent.spawn(self.poll_all_received_events))
            return True

    def poll_all_received_events(self):
        """ This will be triggered once for each `echo_node_alarm_callback`.
        It polls all channels for `EventTransferReceivedSuccess` events,
        adds all new events to the `self.received_transfers` queue and
        respawns `self.echo_node_worker`, if it died. """

        locked = False
        try:
            with Timeout(10):
                locked = self.lock.acquire(blocking=False)
                if not locked:
                    return
                else:
                    received_transfers = self.api.get_channel_events(
                        self.token_address,
                        from_block=self.last_poll_block,
                    )
                    received_transfers = [
                        event for event in received_transfers
                        if event['event'] == 'EventTransferReceivedSuccess'
                    ]
                    for event in received_transfers:
                        transfer = event.copy()
                        transfer.pop('block_number')
                        self.received_transfers.put(transfer)
                    # set last_poll_block after events are enqueued (timeout safe)
                    if received_transfers:
                        self.last_poll_block = max(
                            event['block_number']
                            for event in received_transfers
                        )
                    # increase last_poll_block if the blockchain proceeded
                    delta_blocks = self.api.raiden.get_block_number() - self.last_poll_block
                    if delta_blocks > 1:
                        self.last_poll_block += 1

                    if not self.echo_worker_greenlet.started:
                        log.debug(
                            'restarting echo_worker_greenlet',
                            dead=self.echo_worker_greenlet.dead,
                            successful=self.echo_worker_greenlet.successful(),
                            exception=self.echo_worker_greenlet.exception,
                        )
                        self.echo_worker_greenlet = gevent.spawn(self.echo_worker)
        except Timeout:
            log.info('timeout while polling for events')
        finally:
            if locked:
                self.lock.release()

    def echo_worker(self):
        """ The `echo_worker` works through the `self.received_transfers` queue and spawns
        `self.on_transfer` greenlets for all not-yet-seen transfers. """
        log.debug('echo worker', qsize=self.received_transfers.qsize())
        while self.stop_signal is None:
            if self.received_transfers.qsize() > 0:
                transfer = self.received_transfers.get()
                if transfer in self.seen_transfers:
                    log.debug(
                        'duplicate transfer ignored',
                        initiator=pex(transfer['initiator']),
                        amount=transfer['amount'],
                        identifier=transfer['identifier'],
                    )
                else:
                    self.seen_transfers.append(transfer)
                    self.greenlets.append(gevent.spawn(self.on_transfer, transfer))
            else:
                gevent.sleep(.5)

    def on_transfer(self, transfer):
        """ This handles the echo logic, as described in
        https://github.com/raiden-network/raiden/issues/651:

            - for transfers with an amount that satisfies `amount % 3 == 0`, it sends a transfer
            with an amount of `amount - 1` back to the initiator
            - for transfers with a "lucky number" amount `amount == 7` it does not send anything
            back immediately -- after having received "lucky number transfers" from 7 different
            addresses it sends a transfer with `amount = 49` to one randomly chosen one
            (from the 7 lucky addresses)
            - consecutive entries to the lucky lottery will receive the current pool size as the
            `echo_amount`
            - for all other transfers it sends a transfer with the same `amount` back to the
            initiator """
        echo_amount = 0
        if transfer['amount'] % 3 == 0:
            log.info(
                'ECHO amount - 1',
                initiator=pex(transfer['initiator']),
                amount=transfer['amount'],
                identifier=transfer['identifier'],
            )
            echo_amount = transfer['amount'] - 1

        elif transfer['amount'] == 7:
            log.info(
                'ECHO lucky number draw',
                initiator=pex(transfer['initiator']),
                amount=transfer['amount'],
                identifier=transfer['identifier'],
                poolsize=self.lottery_pool.qsize(),
            )

            # obtain a local copy of the pool
            pool = self.lottery_pool.copy()
            tickets = [pool.get() for _ in range(pool.qsize())]
            assert pool.empty()
            del pool

            if any(ticket['initiator'] == transfer['initiator'] for ticket in tickets):
                assert transfer not in tickets
                log.debug(
                    'duplicate lottery entry',
                    initiator=pex(transfer['initiator']),
                    identifier=transfer['identifier'],
                    poolsize=len(tickets),
                )
                # signal the poolsize to the participant
                echo_amount = len(tickets)

            # payout
            elif len(tickets) == 6:
                log.info('payout!')
                # reset the pool
                assert self.lottery_pool.qsize() == 6
                self.lottery_pool = Queue()
                # add new participant
                tickets.append(transfer)
                # choose the winner
                transfer = random.choice(tickets)
                echo_amount = 49
            else:
                self.lottery_pool.put(transfer)

        else:
            log.debug(
                'echo transfer received',
                initiator=pex(transfer['initiator']),
                amount=transfer['amount'],
                identifier=transfer['identifier'],
            )
            echo_amount = transfer['amount']

        if echo_amount:
            log.debug(
                'sending echo transfer',
                target=pex(transfer['initiator']),
                amount=echo_amount,
                orig_identifier=transfer['identifier'],
                echo_identifier=transfer['identifier'] + echo_amount,
                token_address=pex(self.token_address),
                num_handled_transfers=self.num_handled_transfers + 1,
            )

            self.api.transfer(
                self.api.raiden.default_registry.address,
                self.token_address,
                echo_amount,
                transfer['initiator'],
                identifier=transfer['identifier'] + echo_amount,
            )
        self.num_handled_transfers += 1

    def stop(self):
        self.stop_signal = True
        self.greenlets.append(self.echo_worker_greenlet)
        gevent.wait(self.greenlets)
