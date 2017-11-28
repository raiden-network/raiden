# -*- coding: utf-8 -*-
from __future__ import print_function

import os
import pytest

from raiden.transfer.log import StateChangeLog, StateChangeLogSQLiteBackend
from raiden.network.discovery import Discovery
from raiden.transfer.state_change import Block
from raiden.app import App


def init_database(tmpdir, in_memory_database):
    database_path = ":memory:"
    if not in_memory_database:
        database_path = os.path.join(tmpdir.strpath, 'database.db')
    return StateChangeLog(
        storage_instance=StateChangeLogSQLiteBackend(
            database_path=database_path
        )
    )


@pytest.mark.xfail(reason='Functionality not yet implemented')
def test_recover_from_snapshot(
        blockchain_services,
        tmpdir,
        in_memory_database,
        private_keys):

    change_log = init_database(tmpdir, in_memory_database)

    block_number = 1337
    block = Block(block_number)

    assert change_log.log(block) == 1

    # make snapshot of recent state changes
    change_log.snapshot(change_log.log(block), Block)

    # Setup raiden App instance
    config = App.DEFAULT_CONFIG.copy()
    config['database_path'] = os.path.join(tmpdir.strpath, 'database.db')
    config['privatekey_hex'] = private_keys[0].encode('hex')
    # start App instance and expect recovery to happen automatically from database
    app = App(config, blockchain_services[0], Discovery())

    # assert that the state is recovered
    assert app.raiden._blocknumber == block_number


@pytest.mark.xfail(reason='Functionality not yet implemented')
def test_recover_with_state_change_after_snapshot(
        blockchain_services,
        tmpdir,
        in_memory_database,
        private_keys):

    change_log = init_database(tmpdir, in_memory_database)

    block_number = 1337
    block = Block(block_number)

    assert change_log.log(block) == 1

    # make snapshot of recent state changes
    change_log.snapshot(change_log.log(block), Block)

    # write state change dirctly to database
    # this is to emulate that a state change was written to the log, but was not yet
    # applied before a crash or exit of raiden occured.
    block_number = 7331
    block = Block(block_number)
    change_log.log(block)

    # Setup raiden App instance
    config = App.DEFAULT_CONFIG.copy()
    config['database_path'] = os.path.join(tmpdir.strpath, 'database.db')
    config['privatekey_hex'] = private_keys[0].encode('hex')
    # start App instance and expect recovery to happen automatically from database
    app = App(config, blockchain_services[0], Discovery())

    # assert that the state is recovered
    assert app.raiden._blocknumber == block_number
