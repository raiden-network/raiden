import copy
import random
from collections import deque
from typing import Any, Deque, Dict, List, Set

import gevent
import structlog
from eth_utils import to_checksum_address
from gevent import Greenlet
from gevent.event import Event
from gevent.lock import BoundedSemaphore
from gevent.queue import Queue
from gevent.timeout import Timeout

from raiden.api.python import RaidenAPI
from raiden.tasks import REMOVE_CALLBACK
from raiden.transfer import channel
from raiden.transfer.events import EventPaymentReceivedSuccess
from raiden.transfer.state import ChannelState
from raiden.utils.typing import TokenAddress, TokenAmount

log = structlog.get_logger(__name__)

# number of transfers we will check for duplicates
TRANSFER_MEMORY = 4096


class EchoNode:  # pragma: no unittest
    def __init__(self, api: RaidenAPI, token_address: TokenAddress):
        assert isinstance(api, RaidenAPI)
        self.ready = Event()

        self.api = api
        self.token_address = token_address

        existing_channels = self.api.get_channel_list(
            api.raiden.default_registry.address, self.token_address
        )

        open_channels = [
            channel_state
            for channel_state in existing_channels
            if channel.get_status(channel_state) == ChannelState.STATE_OPENED
        ]

        if len(open_channels) == 0:
            token_proxy = self.api.raiden.proxy_manager.token(self.token_address)
            if not token_proxy.balance_of(self.api.raiden.address) > 0:
                raise ValueError(
                    f"Not enough funds for echo node "
                    f"{to_checksum_address(self.api.raiden.address)} for token "
                    f"{to_checksum_address(self.token_address)}"
                )

            # Using the balance of the node as funds
            funds = TokenAmount(token_proxy.balance_of(self.api.raiden.address))

            self.api.token_network_connect(
                registry_address=self.api.raiden.default_registry.address,
                token_address=self.token_address,
                funds=funds,
                initial_channel_target=10,
                joinable_funds_target=0.5,
            )

        self.num_seen_events = 0
        self.received_transfers: Queue[EventPaymentReceivedSuccess] = Queue()
        self.stop_signal = None  # used to signal REMOVE_CALLBACK and stop echo_workers
        self.greenlets: Set[Greenlet] = set()
        self.lock = BoundedSemaphore()
        self.seen_transfers: Deque[EventPaymentReceivedSuccess] = deque(list(), TRANSFER_MEMORY)
        self.num_handled_transfers = 0
        self.lottery_pool = Queue()

        # register ourselves with the raiden alarm task
        self.api.raiden.alarm.register_callback(self.echo_node_alarm_callback)
        self.echo_worker_greenlet = gevent.spawn(self.echo_worker)
        log.info("Echo node started")

    def echo_node_alarm_callback(self, block: Dict[str, Any]):
        """ This can be registered with the raiden AlarmTask.
        If `EchoNode.stop()` is called, it will give the return signal to be removed from
        the AlarmTask callbacks.
        """
        if not self.ready.is_set():
            self.ready.set()
        log.debug(
            "echo_node callback",
            node=to_checksum_address(self.api.address),
            block_number=block["number"],
        )
        if self.stop_signal is not None:
            return REMOVE_CALLBACK
        else:
            self.greenlets.add(gevent.spawn(self.poll_all_received_events))
            return True

    def poll_all_received_events(self) -> None:
        """ This will be triggered once for each `echo_node_alarm_callback`.
        It polls all channels for `EventPaymentReceivedSuccess` events,
        adds all new events to the `self.received_transfers` queue and
        respawns `self.echo_worker`, if it died. """

        locked = False
        try:
            with Timeout(10):
                locked = self.lock.acquire(blocking=False)
                if not locked:
                    return
                else:
                    received_transfers: List[Event] = self.api.get_raiden_events_payment_history(
                        token_address=self.token_address, offset=self.num_seen_events
                    )

                    received_transfers = [
                        event
                        for event in received_transfers
                        if type(event) == EventPaymentReceivedSuccess
                    ]

                    for event in received_transfers:
                        transfer = copy.deepcopy(event)
                        self.received_transfers.put(transfer)

                    # set last_poll_block after events are enqueued (timeout safe)
                    if received_transfers:
                        self.num_seen_events += len(received_transfers)

                    if not bool(self.echo_worker_greenlet):
                        log.debug(
                            "Restarting echo_worker_greenlet",
                            node=to_checksum_address(self.api.address),
                            dead=self.echo_worker_greenlet.dead,
                            successful=self.echo_worker_greenlet.successful(),
                            exception=self.echo_worker_greenlet.exception,
                        )
                        self.echo_worker_greenlet = gevent.spawn(self.echo_worker)
        except Timeout:
            log.info("Timeout while polling for events")
        finally:
            if locked:
                self.lock.release()

    def echo_worker(self):
        """ The `echo_worker` works through the `self.received_transfers` queue and spawns
        `self.on_transfer` greenlets for all not-yet-seen transfers. """
        log.debug("echo worker", qsize=self.received_transfers.qsize())
        while self.stop_signal is None:
            if self.received_transfers.qsize() > 0:
                transfer = self.received_transfers.get()
                if transfer in self.seen_transfers:
                    log.debug(
                        "Duplicate transfer ignored",
                        node=to_checksum_address(self.api.address),
                        initiator=to_checksum_address(transfer.initiator),
                        amount=transfer.amount,
                        identifier=transfer.identifier,
                    )
                else:
                    self.seen_transfers.append(transfer)
                    self.greenlets.add(gevent.spawn(self.on_transfer, transfer))
            else:
                gevent.sleep(0.5)

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
            initiator
        """
        echo_amount = 0
        if transfer.amount % 3 == 0:
            log.info(
                "Received amount divisible by three",
                node=to_checksum_address(self.api.address),
                initiator=to_checksum_address(transfer.initiator),
                amount=transfer.amount,
                identifier=transfer.identifier,
            )
            echo_amount = TokenAmount(transfer.amount - 1)

        elif transfer.amount == 7:
            log.info(
                "Received lottery entry",
                node=to_checksum_address(self.api.address),
                initiator=to_checksum_address(transfer.initiator),
                amount=transfer.amount,
                identifier=transfer.identifier,
                poolsize=self.lottery_pool.qsize(),
            )

            # obtain a local copy of the pool
            pool = self.lottery_pool.copy()
            tickets = [pool.get() for _ in range(pool.qsize())]
            assert pool.empty()
            del pool

            if any(ticket.initiator == transfer.initiator for ticket in tickets):
                assert transfer not in tickets
                log.debug(
                    "Duplicate lottery entry",
                    node=to_checksum_address(self.api.address),
                    initiator=to_checksum_address(transfer.initiator),
                    identifier=transfer.identifier,
                    poolsize=len(tickets),
                )
                # signal the poolsize to the participant
                echo_amount = len(tickets)

            # payout
            elif len(tickets) == 6:
                log.info("Payout!")
                # reset the pool
                assert self.lottery_pool.qsize() == 6
                self.lottery_pool = Queue()

                # add the new participant
                tickets.append(transfer)

                # choose the winner
                transfer = random.choice(tickets)
                echo_amount = 49
            else:
                self.lottery_pool.put(transfer)

        else:
            log.debug(
                "Received transfer",
                node=to_checksum_address(self.api.address),
                initiator=to_checksum_address(transfer.initiator),
                amount=transfer.amount,
                identifier=transfer.identifier,
            )
            echo_amount = transfer.amount

        if echo_amount:
            echo_identifier = transfer.identifier + echo_amount
            log.debug(
                "Sending echo transfer",
                node=to_checksum_address(self.api.address),
                target=to_checksum_address(transfer.initiator),
                amount=echo_amount,
                original_identifier=transfer.identifier,
                echo_identifier=echo_identifier,
                token_address=to_checksum_address(self.token_address),
                num_handled_transfers=self.num_handled_transfers + 1,
            )

            self.api.transfer(
                registry_address=self.api.raiden.default_registry.address,
                token_address=self.token_address,
                amount=echo_amount,
                target=transfer.initiator,
                identifier=echo_identifier,
            )

        self.num_handled_transfers += 1

    def stop(self):
        self.stop_signal = True
        self.greenlets.add(self.echo_worker_greenlet)
        gevent.joinall(self.greenlets, raise_error=True)
