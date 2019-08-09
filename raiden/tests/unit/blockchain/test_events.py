from unittest.mock import Mock

from hexbytes import HexBytes

from raiden.blockchain.events import BlockchainEvents
from raiden.blockchain.filters import StatelessFilter
from raiden.tests.utils.events import check_dict_nested_attrs
from raiden.tests.utils.factories import UNIT_CHAIN_ID
from raiden.utils.typing import BlockNumber


def stub_web3(logs):
    stub = Mock()
    stub.eth.getLogs = lambda *_: logs
    return stub


event1 = {
    "args": {
        "channel_identifier": 1,
        "participant1": HexBytes("0x88bBbcD1De457Adc982aE21a18d411FBBfA08a35"),
        "participant2": HexBytes("0x4b8C93B34109762922EdeAcB49e6A67703C4bea4"),
        "settle_timeout": 39,
    },
    "event": "ChannelOpened",
    "logIndex": 0,
    "transactionIndex": 0,
    "transactionHash": HexBytes(
        "0x738c8eaa7f2dd41d2df5783b7d4d4b3ef8d12b592264a08da5dbd1b72bd7c094"
    ),
    "address": "0x06D434580D78aBe5f9Ba085f99c16F76E0bfa970",
    "blockHash": HexBytes("0x63fba9aa7736d7cf4115171f8801c78c9379eb5ea2bde3bc444d13f36cf5564f"),
    "blockNumber": 235,
}

event_logs = [
    {
        "address": "0x06D434580D78aBe5f9Ba085f99c16F76E0bfa970",
        "topics": [
            HexBytes("0x669a4b0ac0b9994c0f82ed4dbe07bb421fe74e5951725af4f139c7443ebf049d"),
            HexBytes("0x0000000000000000000000000000000000000000000000000000000000000001"),
            HexBytes("0x00000000000000000000000088bbbcd1de457adc982ae21a18d411fbbfa08a35"),
            HexBytes("0x0000000000000000000000004b8c93b34109762922edeacb49e6a67703c4bea4"),
        ],
        "data": "0x0000000000000000000000000000000000000000000000000000000000000027",
        "blockNumber": 235,
        "transactionHash": HexBytes(
            "0x738c8eaa7f2dd41d2df5783b7d4d4b3ef8d12b592264a08da5dbd1b72bd7c094"
        ),
        "transactionIndex": 0,
        "blockHash": HexBytes(
            "0x63fba9aa7736d7cf4115171f8801c78c9379eb5ea2bde3bc444d13f36cf5564f"
        ),
        "logIndex": 0,
        "removed": False,
    }
]


def test_blockchain_events(contract_manager):
    # TODO Expand this test: multiple listeners, removed listeners, multiple/missed events.
    # As it is now it only covers the classès helper functions in raiden.utils.filters properly.
    blockchain_events = BlockchainEvents(UNIT_CHAIN_ID)
    abi = contract_manager.get_contract_abi("TokenNetwork")

    stateless_filter = StatelessFilter(
        web3=stub_web3(event_logs), filter_params=dict(toBlock="pending")
    )
    blockchain_events.add_event_listener(event_name="Block", eth_filter=stateless_filter, abi=abi)

    events = list(blockchain_events.poll_blockchain_events(block_number=BlockNumber(235)))

    assert len(events) == 1
    assert len(stateless_filter.get_all_entries(BlockNumber(235))) == 1
    assert check_dict_nested_attrs(events[0].event_data, event1)

    blockchain_events.uninstall_all_event_listeners()
