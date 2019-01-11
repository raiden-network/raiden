from typing import Dict, List

import pytest
from web3 import Web3

from pathfinding_service.utils.blockchain_listener import (
    BlockchainListener,
    create_channel_event_topics,
)


def test_blockchain_listener(
    web3: Web3,
    wait_for_blocks,
    generate_raiden_clients,
    blockchain_listener: BlockchainListener,
    ethereum_tester,
):
    blockchain_listener.required_confirmations = 4
    blockchain_listener.start()
    blockchain_listener.wait_sync()

    unconfirmed_channel_open_events: List[Dict] = []
    confirmed_channel_open_events: List[Dict] = []

    blockchain_listener.add_unconfirmed_listener(
        create_channel_event_topics(),
        unconfirmed_channel_open_events.append,
    )
    blockchain_listener.add_confirmed_listener(
        create_channel_event_topics(),
        confirmed_channel_open_events.append,
    )

    # create unconfirmed channel
    c1, c2 = generate_raiden_clients(2)
    c1.open_channel(c2.address)

    # the unconfirmed event should be available directly
    wait_for_blocks(0)
    assert len(unconfirmed_channel_open_events) == 1
    assert unconfirmed_channel_open_events[0]['args']['participant1'] == c1.address
    assert unconfirmed_channel_open_events[0]['args']['participant2'] == c2.address

    # the confirmed event should be available after 4 more blocks as set above
    assert len(confirmed_channel_open_events) == 0
    wait_for_blocks(4)
    assert len(confirmed_channel_open_events) == 1
    assert confirmed_channel_open_events[0]['args']['participant1'] == c1.address
    assert confirmed_channel_open_events[0]['args']['participant2'] == c2.address

    blockchain_listener.stop()


def test_blockchain_listener_nonexistant_contract(
    web3: Web3,
    wait_for_blocks,
    generate_raiden_clients,
    blockchain_listener: BlockchainListener,
    ethereum_tester,
):
    blockchain_listener.required_confirmations = 4
    blockchain_listener.contract_address = '0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa'
    blockchain_listener.start()
    blockchain_listener.wait_sync()

    unconfirmed_channel_open_events: List[Dict] = []
    confirmed_channel_open_events: List[Dict] = []

    blockchain_listener.add_unconfirmed_listener(
        create_channel_event_topics(),
        unconfirmed_channel_open_events.append,
    )
    blockchain_listener.add_confirmed_listener(
        create_channel_event_topics(),
        confirmed_channel_open_events.append,
    )

    # create unconfirmed channel
    c1, c2 = generate_raiden_clients(2)
    c1.open_channel(c2.address)

    # no unconfirmed event should be available
    wait_for_blocks(0)
    assert len(unconfirmed_channel_open_events) == 0

    # no confirmed event should be available after 4 more blocks
    wait_for_blocks(4)
    assert len(confirmed_channel_open_events) == 0

    blockchain_listener.stop()


def test_reorg(
    web3: Web3,
    wait_for_blocks,
    generate_raiden_clients,
    blockchain_listener: BlockchainListener,
    ethereum_tester,
):
    blockchain_listener.required_confirmations = 5
    blockchain_listener.start()
    blockchain_listener.wait_sync()

    unconfirmed_channel_open_events: List[Dict] = []
    blockchain_listener.add_unconfirmed_listener(
        create_channel_event_topics(),
        unconfirmed_channel_open_events.append,
    )

    c1, c2 = generate_raiden_clients(2)
    snapshot_id = web3.testing.snapshot()

    # create unconfirmed channel
    c1.open_channel(c2.address)
    wait_for_blocks(0)
    assert len(unconfirmed_channel_open_events) == 1
    assert unconfirmed_channel_open_events[0]['args']['participant1'] == c1.address
    assert unconfirmed_channel_open_events[0]['args']['participant2'] == c2.address

    # remove unconfirmed channel opening with reorg
    web3.testing.revert(snapshot_id)

    # run the BlockchainListener again, it should have a lower head_number now
    old_head_number = blockchain_listener.unconfirmed_head_number
    wait_for_blocks(0)
    new_head_number = blockchain_listener.unconfirmed_head_number

    assert old_head_number > new_head_number

    # test that a chain reorg of one block is handled
    # this created a channel first, then reverts and creates a different channel
    unconfirmed_channel_open_events.clear()
    c1.open_channel(c2.address)
    wait_for_blocks(0)
    assert len(unconfirmed_channel_open_events) == 1
    assert unconfirmed_channel_open_events[0]['args']['participant1'] == c1.address
    assert unconfirmed_channel_open_events[0]['args']['participant2'] == c2.address
    web3.testing.revert(snapshot_id)
    c2.open_channel(c1.address)
    wait_for_blocks(0)
    assert len(unconfirmed_channel_open_events) == 2
    assert unconfirmed_channel_open_events[1]['args']['participant1'] == c2.address
    assert unconfirmed_channel_open_events[1]['args']['participant2'] == c1.address

    web3.testing.revert(snapshot_id)

    # test a big chain reorg (> required_confirmations)
    confirmed_channel_open_events: List[Dict] = []
    blockchain_listener.add_confirmed_listener(
        create_channel_event_topics(),
        confirmed_channel_open_events.append,
    )
    c1.open_channel(c2.address)

    # create a new event and wait till it's confirmed
    wait_for_blocks(5)

    assert len(confirmed_channel_open_events) == 1

    # revert the chain, this should kill the process
    web3.testing.revert(snapshot_id)

    with pytest.raises(SystemExit):
        wait_for_blocks(0)

    blockchain_listener.stop()
