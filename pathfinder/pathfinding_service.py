# -*- coding: utf-8 -*-
import logging
import sys
import traceback
from typing import Dict

import gevent

from pathfinder.blockchain import BlockchainMonitor
from pathfinder.gevent_error_handler import register_error_handler
from pathfinder.token_network import TokenNetwork
from pathfinder.transport import MatrixTransport
from pathfinder.utils.types import Address

log = logging.getLogger(__name__)


def error_handler(context, exc_info):
    log.fatal("Unhandled exception terminating the program")
    traceback.print_exception(
        etype=exc_info[0],
        value=exc_info[1],
        tb=exc_info[2]
    )
    sys.exit()


class PathfindingService(gevent.Greenlet):
    def __init__(
        self,
        transport: MatrixTransport,
        blockchain: BlockchainMonitor
    ) -> None:
        super().__init__()
        self.transport = transport
        self.blockchain = blockchain
        self.is_running = gevent.event.Event()
        self.transport.add_message_callback(lambda message: self.on_message_event(message))
        self.token_networks: Dict[Address, TokenNetwork] = {}

    def _run(self):
        register_error_handler(error_handler)
        self.transport.start()
        # self.blockchain.start()

        self.is_running.wait()

    def stop(self):
        self.is_running.set()

    def on_message_event(self, message):
        """This handles messages received over the Transport"""
        print(message)
