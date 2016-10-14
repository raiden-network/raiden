#!/usr/bin/env python
from __future__ import print_function
import sys
import os

from ethereum import tester, slogging


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

from raiden.utils import privatekey_to_address
from raiden.tests.utils.tester import (
    new_channelmanager,
    new_decodertester,
)
root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_decode_singletransfer(
        private_keys,
        settle_timeout,
        tester_state,
        tester_token,
        tester_events,
        tester_registry):

    slogging.configure(':INFO,eth.vm:TRACE')

    start_block = tester_state.block.number
    privatekey0 = private_keys[0]
    privatekey1 = private_keys[1]
    address0 = privatekey_to_address(privatekey0)
    address1 = privatekey_to_address(privatekey1)
    unknow_key = tester.k3

    channel_manager = new_channelmanager(
        privatekey0,
        tester_state,
        tester_events.append,
        tester_registry,
        tester_token,
    )

    dtester = new_decodertester(
        privatekey0,
        privatekey1,
        tester_state,
        tester_events.append,
        channel_manager,
        settle_timeout,
    )

    # vmtrace is at stderr, so let's see where the faulty vm trace starts
    eprint("\n\n\n<---------------------->\n\n\n")
    assert dtester.foo(sender=privatekey0) == 19
    # dtester.testCloseSingleTransfer(sender=privatekey0)
